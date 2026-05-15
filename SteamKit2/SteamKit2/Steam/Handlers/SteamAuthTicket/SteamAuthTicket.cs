using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.IO.Hashing;
using SteamKit2.Internal;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Threading;

namespace SteamKit2
{
    /// <summary>
    /// This handler generates auth session ticket and handles its verification by steam.
    /// </summary>
    public sealed partial class SteamAuthTicket : ClientMsgHandler
    {
        /// <summary>
        /// Represents the information about the generated authentication session ticket.
        /// </summary>
        public enum TicketType : uint
        {
            /// <summary>
            /// Default auth session ticket type.
            /// </summary>
            AuthSession = 2,

            /// <summary>
            /// Web API auth session ticket type.
            /// </summary>
            WebApiTicket = 5
        }

        //According to https://partner.steamgames.com/doc/api/ISteamUser#GetTicketForWebApiResponse_t the m_rgubTicket size is 2560 bytes
        private const int WebApiTicketSize = 2560;

        private readonly Dictionary<EMsg, Action<IPacketMsg>> DispatchMap;
        private readonly Queue<byte[]> GameConnectTokens = new();
        private readonly Dictionary<uint, List<CMsgAuthTicket>> TicketsByGame = [];
        private readonly object TicketChangeLock = new();
        private readonly int _steamPipe = Random.Shared.Next( 1, 1000000 );
        private static uint Sequence;
        private uint _requestSequence;
        private uint _requestServerSequence;


        /// <summary>
        /// Initializes all necessary callbacks.
        /// </summary>
        public SteamAuthTicket()
        {
            DispatchMap = new Dictionary<EMsg, Action<IPacketMsg>>
            {
                { EMsg.ClientAuthListAck, HandleTicketAcknowledged },
                { EMsg.ClientTicketAuthComplete, HandleTicketAuthComplete },
                { EMsg.ClientGameConnectTokens, HandleGameConnectTokens },
                { EMsg.ClientLogOff, HandleLogOffResponse }
            };
        }

        /// <summary>
        /// Performs <see href="https://partner.steamgames.com/doc/api/ISteamUser#GetAuthSessionTicket">session ticket</see> generation and validation for specified <paramref name="appid"/>.
        /// </summary>
        /// <param name="appid">Game to generate ticket for.</param>
        /// <returns>A task representing the asynchronous operation. The task result contains a <see cref="TicketInfo"/>
        /// object that provides details about the generated valid authentication session ticket.</returns>
        public Task<TicketInfo> GetAuthSessionTicket( uint appid )
        {
            return GetAuthSessionTicketInternal( appid, TicketType.AuthSession, string.Empty );
        }

        /// <summary>
        /// Performs <see href="https://partner.steamgames.com/doc/api/ISteamUser#GetAuthTicketForWebApi">WebApi session ticket</see> generation and validation for specified <paramref name="appid"/> and  <paramref name="identity"/> .
        /// </summary>
        /// <param name="appid">Game to generate ticket for.</param>
        /// <param name="identity">The identity of the remote service that will authenticate the ticket. The service should provide a string identifier.</param>
        /// <returns>A task representing the asynchronous operation. The task result contains a <see cref="TicketInfo"/>
        /// object that provides details about the generated valid authentication WebApi session ticket.</returns>
        public Task<TicketInfo> GetAuthTicketForWebApi( uint appid, string identity )
        {
            return GetAuthSessionTicketInternal( appid, TicketType.WebApiTicket, identity );
        }

        internal async Task<TicketInfo> GetAuthSessionTicketInternal( uint appid, TicketType ticketType, string? identity )
        {
            if ( Client.CellID == null ) throw new Exception( "User not logged in." );

            var apps = Client.GetHandler<SteamApps>() ?? throw new Exception( "Steam Apps instance was null." );
            var appTicket = await apps.GetAppOwnershipTicket( appid );

            if ( appTicket.Result != EResult.OK ) throw new Exception( $"Failed to obtain app ownership ticket. Result: {appTicket.Result}. The user may not own the game or there was an error." );

            if ( GameConnectTokens.TryDequeue( out var token ) )
            {
                using var stream = new MemoryStream( appTicket.Ticket );
                using var reader = new BinaryReader( stream );
                
                var authTicket = BuildAuthTicket( token, Client.PublicIP, ticketType );
                reader.ReadUInt32(); // length
                reader.ReadUInt32(); // version
                var steamId = reader.ReadUInt64();
                var ticketAppId = reader.ReadUInt32();
                
                // Steam add the 'str:' prefix to the identity string itself and appends a null terminator
                var serverSecret = string.IsNullOrEmpty( identity )
                    ? null
                    : Encoding.UTF8.GetBytes( $"str:{identity}\0" );
                var ticket = await VerifyTicket( ticketAppId, steamId, authTicket, serverSecret, out var crc );
                
                // Verify just in case
                if ( ticket.ActiveTicketsCRC.Any( x => x == crc ) )
                {
                    var tok = CombineTickets( authTicket, appTicket.Ticket, ticketType is TicketType.WebApiTicket );
                    return new TicketInfo( this, ticketAppId, tok );
                }
                else
                {
                    throw new Exception( "Ticket verification failed." );
                }
            }
            else
            {
                throw new Exception( "There's no available game connect tokens left." );
            }
        }

        public async Task CancelGameTickets( uint gameId )
        {
            bool changed = false;
            lock ( TicketChangeLock )
            {
                if ( TicketsByGame.TryGetValue( gameId, out var tickets ) )
                {
                    tickets.RemoveAll( x => x.gameid == gameId && x.steamid == 0 );
                    changed = true;
                }
            }

            if ( !changed )
            {
                return;
            }
            
            await SendTickets();
        }

        internal void CancelAuthTicket( TicketInfo authTicket )
        {
            lock ( TicketChangeLock )
            {
                if ( TicketsByGame.TryGetValue( authTicket.AppID, out var tickets ) )
                {
                    tickets.RemoveAll( x => x.ticket_crc == authTicket.TicketCRC );
                }
            }

            SendTickets();
        }

        private static byte[] CombineTickets( byte[] authTicket, byte[] appTicket, bool padToWebApiSize )
        {
            var len = appTicket.Length;

            int rawSize = authTicket.Length + 4 + appTicket.Length;
            int target  = padToWebApiSize ? Math.Max(rawSize, WebApiTicketSize) : rawSize;

            var token = new byte[ target ];
            var mem = token.AsSpan();
            authTicket.CopyTo( mem );
            MemoryMarshal.Write( mem[ authTicket.Length.. ], in len );
            appTicket.CopyTo( mem[ ( authTicket.Length + 4 ).. ] );

            // The WebApiTicket is always 2560 bytes long, but everything after the tickets is just a trash after memory allocation
            if (padToWebApiSize && rawSize < target)
                RandomNumberGenerator.Fill(mem[rawSize..target]);

            return token;
        }

        /// <summary>
        /// Handles generation of auth ticket.
        /// </summary>
        private static byte[] BuildAuthTicket( byte[] gameConnectToken, IPAddress? publicIp, TicketType ticketType )
        {
            const int sessionSize =
                4 + // unknown, always 1
                4 + // TicketType, 2 or 5
                4 + // public IP v4, optional
                4 + // private IP v4, optional
                4 + // timestamp & uint.MaxValue
                4;  // sequence

            using var stream = new MemoryStream( gameConnectToken.Length + 4 + sessionSize );
            using ( var writer = new BinaryWriter( stream ) )
            {
                writer.Write( gameConnectToken.Length );
                writer.Write( gameConnectToken );

                writer.Write( sessionSize );
                writer.Write( 1 );
                writer.Write( ( uint )ticketType );
                
                writer.Write( publicIp == null ? 0 : NetHelpers.GetIPAddressAsUInt( publicIp ) );
                writer.Write( 0u );
                writer.Write( ( uint )Stopwatch.GetTimestamp() );
                // Use Interlocked to safely increment the sequence number
                writer.Write( Interlocked.Increment( ref Sequence ) );
            }
            return stream.ToArray();
        }

        private Task<TicketAcceptedCallback> VerifyTicket( uint appid, ulong steamId, byte[] authToken, byte[]? serverSecret, out uint crc )
        {
            crc = BitConverter.ToUInt32( Crc32.Hash( authToken ), 0 );
            lock ( TicketChangeLock )
            {
                if ( !TicketsByGame.TryGetValue( appid, out var items ) )
                {
                    items = [];
                    TicketsByGame[ appid ] = items;
                }

                var isOurTicket = steamId == Client.GetHandler<SteamUser>()!.SteamID!;
                var ticket = new CMsgAuthTicket
                {
                    estate = isOurTicket ? 0u : 1u,
                    steamid = isOurTicket ? 0 : steamId,
                    h_steam_pipe = ( uint )_steamPipe,
                    gameid = appid,
                    ticket = authToken,
                    ticket_crc = crc,
                    server_secret = serverSecret
                };

                if ( !isOurTicket )
                {
                    var existingTicket = items.FindIndex( t => t.steamid == ticket.steamid && t.gameid == appid );
                    if ( existingTicket != -1 )
                    {
                        items.RemoveAt( existingTicket );
                    }
                }
                
                // Add ticket to specified games list
                items.Add( ticket );
            }

            return SendTickets();
        }
        private async Task<TicketAcceptedCallback> SendTickets()
        {
            var auth = new ClientMsgProtobuf<CMsgClientAuthList>( EMsg.ClientAuthList );
            auth.Body.tokens_left = ( uint )GameConnectTokens.Count;
            auth.Body.last_request_seq = _requestSequence;
            auth.Body.message_sequence = ++_requestSequence;
            auth.Body.last_request_seq_from_server = _requestServerSequence;

            lock ( TicketChangeLock )
            {
                auth.Body.app_ids.AddRange( TicketsByGame.Keys );
                // Flatten dictionary into ticket list
                auth.Body.tickets.AddRange( TicketsByGame.Values.SelectMany( x => x ) );
            }

            auth.SourceJobID = Client.GetNextJobID();
            Client.Send( auth );

            var callback = await new AsyncJob<TicketAcceptedCallback>( Client, auth.SourceJobID );
            _requestServerSequence = callback.MessageSequence;

            return callback;
        }

        /// <summary>
        /// Handles a client message. This should not be called directly.
        /// </summary>
        /// <param name="packetMsg">The packet message that contains the data.</param>
        public override void HandleMsg( IPacketMsg packetMsg )
        {
            ArgumentNullException.ThrowIfNull( packetMsg );

            if ( DispatchMap.TryGetValue( packetMsg.MsgType, out var handlerFunc ) )
            {
                handlerFunc( packetMsg );
            }
        }

        #region ClientMsg Handlers
        private void HandleLogOffResponse( IPacketMsg packetMsg )
        {
            // Clear all game connect tokens on client log off
            GameConnectTokens.Clear();
        }
        private void HandleGameConnectTokens( IPacketMsg packetMsg )
        {
            var body = new ClientMsgProtobuf<CMsgClientGameConnectTokens>( packetMsg ).Body;

            // Add tokens
            foreach ( var tok in body.tokens )
            {
                GameConnectTokens.Enqueue( tok );
            }

            // Keep only required amount, discard old entries
            while ( GameConnectTokens.Count > body.max_tokens_to_keep )
            {
                GameConnectTokens.TryDequeue( out _ );
            }
        }
        private void HandleTicketAuthComplete( IPacketMsg packetMsg )
        {
            // Ticket successfully used to authorize user
            var complete = new ClientMsgProtobuf<CMsgClientTicketAuthComplete>( packetMsg );
            var inUse = new TicketAuthCompleteCallback( complete.TargetJobID, complete.Body );
            Client.PostCallback( inUse );
        }
        private void HandleTicketAcknowledged( IPacketMsg packetMsg )
        {
            // Ticket acknowledged as valid by Steam
            var authAck = new ClientMsgProtobuf<CMsgClientAuthListAck>( packetMsg );
            var acknowledged = new TicketAcceptedCallback( authAck.TargetJobID, authAck.Body );
            Client.PostCallback( acknowledged );
        }
        #endregion
    }
}
