-- | Waiting for a socket to become ready on Windows, through
--   @IOCTL_AFD_POLL@ on the AFD driver beneath Winsock, as libuv,
--   wepoll and mio do.  It completes on the I/O manager's port like any
--   overlapped operation on the socket.
module Network.Socket.Win32.AfdPoll (
    afdRead,
    afdWrite,
    afdWait,
    afdWaitSTM,
) where

import Control.Concurrent (forkIOWithUnmask, killThread)
import Control.Monad (when)
import Data.Bits ((.&.))
import Control.Concurrent.STM (STM, atomically, newEmptyTMVarIO, putTMVar, readTMVar, throwSTM)
import qualified Control.Exception as E
import Foreign.C.Types (CInt (..), CUIntPtr (..), CULong (..))
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr, castPtr, wordPtrToPtr)
import qualified GHC.Event.Windows as Mgr

import Data.Word (Word32)
import Network.Socket.Cbits (wsaOperationAborted)
import Network.Socket.Types

-- | RECEIVE, DISCONNECT, ACCEPT, ABORT and LOCAL_CLOSE: whatever a read
--   would not block on, as POSIX readiness reports it.
afdRead :: CULong
afdRead = 0x0001 + 0x0008 + 0x0080 + 0x0010 + 0x0020

-- | SEND, CONNECT_FAIL, ABORT and LOCAL_CLOSE.
afdWrite :: CULong
afdWrite = 0x0004 + 0x0100 + 0x0010 + 0x0020

-- | Blocking until one of the events is reported on the socket.  An
--   asynchronous exception ends the wait: 'Mgr.withOverlapped' cancels
--   the poll.  A poll can end with events not asked for, such as SEND
--   for a read; it is then made again, as wepoll and mio do.  So is one
--   Windows cancelled while the socket is open: see
--   'Network.Socket.Win32.Internal.withOverlappedSocket'.
afdWait :: String -> CULong -> Socket -> IO ()
afdWait name events s = withFdSocket s $ \fd -> do
    size <- c_afd_poll_info_size
    allocaBytes (fromIntegral size) $ \info -> do
        let loop = do
                r <- pollOnce fd info
                case r of
                    Mgr.IOFailed (Just err)
                        | c_winsock_code (fromIntegral err) == wsaOperationAborted -> do
                            cur <- unsafeFdSocket s
                            if cur == invalidSocket then throwFailure r else loop
                    _ -> do
                        throwFailure r
                        got <- c_afd_poll_events info
                        when (got .&. events == 0) loop
        loop
  where
    throwFailure r = fmap (const ()) $ Mgr.withException name $ return r
    pollOnce fd info =
        Mgr.withOverlapped name (wordPtrToPtr $ fromIntegral fd) 0
            (\ov -> do
                rc <- c_afd_poll fd events info (castPtr ov)
                return $
                    if rc == 0 || rc == errorIoPending
                        then Mgr.CbPending
                        else Mgr.CbError (fromIntegral rc))
            (\err _ ->
                if err == 0 then Mgr.ioSuccess 0 else Mgr.ioFailed err)
    errorIoPending = 997

-- | 'afdWait' as an STM action, and an action cancelling it.  The wait
--   runs in a thread of its own, which the cancel kills.  That thread is
--   unmasked: one inheriting an uninterruptible mask could not be killed,
--   and the cancel would wait for the poll.
afdWaitSTM :: String -> CULong -> Socket -> IO (STM (), IO ())
afdWaitSTM name events s = do
    var <- newEmptyTMVarIO
    tid <- forkIOWithUnmask $ \unmask -> do
        r <- E.try $ unmask $ afdWait name events s
        atomically $ putTMVar var (r :: Either E.IOException ())
    return (readTMVar var >>= either throwSTM return, killThread tid)

foreign import ccall unsafe "hsnet_winsock_code"
    c_winsock_code :: Word32 -> CInt

foreign import ccall unsafe "hsnet_afd_poll_info_size"
    c_afd_poll_info_size :: IO CInt
foreign import ccall unsafe "hsnet_afd_poll"
    c_afd_poll :: CSocket -> CULong -> Ptr () -> Ptr () -> IO CInt
foreign import ccall unsafe "hsnet_afd_poll_events"
    c_afd_poll_events :: Ptr () -> IO CULong
