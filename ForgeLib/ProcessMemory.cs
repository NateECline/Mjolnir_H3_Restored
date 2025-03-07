﻿//#define KERNEL32
#define NTDLL

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace ForgeLib {
    public class ProcessMemory {
        IntPtr pHandle;
        Process process;
        Dictionary<string, IntPtr> modules = new Dictionary<string, IntPtr>();

        public bool Connected => process != null && !process.HasExited;
        public IntPtr MCCAddr;
        static bool isAdmin;
        static bool is64bit;

        static ProcessMemory() {
            isAdmin = IsUserAnAdmin();
        }

        static void DebugMsg(string message) {
            Debug.WriteLine(message);
            ForgeBridge.lastError += message + "\n";
        }

        public bool OpenProcess(int pid) {
            if (!isAdmin) DebugMsg("WARNING: This program may not be running with admin privileges. Run Blender as administrator.");
            if (pid <= 0) { DebugMsg($"ERROR: Invalid process ID: {pid}"); return false; }
            if (process != null && process.Id == pid) return true;
            try {
                process = Process.GetProcessById(pid);
                if (process != null && !process.Responding) { DebugMsg("ERROR: OpenProcess: Process is not responding or null."); return false; }
                pHandle = OpenProcess(2035711u, true, pid);
                MCCAddr = pHandle;
                try { Process.EnterDebugMode(); } catch (Win32Exception ex) { DebugMsg("ERROR:" + ex); }
                if (pHandle == IntPtr.Zero || process == null) {
                    DebugMsg($"ERROR: Failed to open process {pid} (Win32Error {Marshal.GetLastWin32Error()})");
                    try { Process.LeaveDebugMode(); } catch (Win32Exception ex) { DebugMsg("ERROR:" + ex); }
                    process = null;
                    return false;
                }

                is64bit = Environment.Is64BitOperatingSystem && IsWow64Process(pHandle, out var lpSystemInfo) && !lpSystemInfo;
                const string architectureError = "WARNING: Game is %s, but dll is %s! Dll needs to be recompiled for correct architecture.";
                if (is64bit && IntPtr.Size != 8) DebugMsg(string.Format(architectureError, "x64", "x86"));
                else if (!is64bit && IntPtr.Size == 8) DebugMsg(string.Format(architectureError, "x86", "x64"));

                modules.Clear();
                foreach (ProcessModule module in process.Modules) {
                    string moduleName = module.ModuleName;
                    if (!modules.ContainsKey(moduleName)) modules.Add(moduleName, module.BaseAddress);
                }

                return true;
            }
            catch (Exception ex) {
                DebugMsg("ERROR: Failed to open process:\n" + ex);
                return false;
            }
        }

        public List<UIntPtr> AoBScan(UIntPtr startAddress, UIntPtr endAddress, byte[] pattern, string mask = null)
        {
            List<UIntPtr> results = new List<UIntPtr>();
            int bufferSize = 4096; // Read memory in chunks

            byte[] buffer = new byte[bufferSize];

            for (UIntPtr address = startAddress; address.ToUInt64() < endAddress.ToUInt64(); address = (UIntPtr)(address.ToUInt64() + (ulong)bufferSize))
            {
                if (!TryReadBytes(address, buffer, bufferSize))
                    continue;

                for (int i = 0; i < bufferSize - pattern.Length; i++)
                {
                    if (PatternMatches(buffer, i, pattern, mask))
                    {
                        results.Add((UIntPtr)(address.ToUInt64() + (ulong)i));
                    }
                }
            }
            return results;
        }

        private bool PatternMatches(byte[] buffer, int index, byte[] pattern, string mask)
        {
            for (int i = 0; i < pattern.Length; i++)
            {
                if (mask != null && mask[i] == '?')
                    continue; // Wildcard, ignore check

                if (buffer[index + i] != pattern[i])
                    return false;
            }
            return true;
        }


        public void CloseProcess() {
            _ = pHandle;
            if (0 == 0) {
                CloseHandle(pHandle);
                process = null;
            }
        }


        [ThreadStatic] static byte[] by = new byte[1];
        [ThreadStatic] static byte[] by4 = new byte[4];
        [ThreadStatic] static byte[] by16 = new byte[16];

        public bool TryGetModuleBaseAddress(string moduleName, out UIntPtr address) {
            if (modules.TryGetValue(moduleName, out IntPtr ptr)) {
                unsafe { address = (UIntPtr)ptr.ToPointer(); }
                return true;
            }
            address = UIntPtr.Zero;
            return false;
        }

        public bool TryReadBytes(UIntPtr ptr, byte[] bytes, int count) {
#if KERNEL32
            if (ReadProcessMemory(pHandle, ptr, bytes, (UIntPtr)checked((ulong)count), IntPtr.Zero))
                return true;
#elif NTDLL
            if (NtReadVirtualMemory(pHandle, ptr, bytes, (uint)count, UIntPtr.Zero) < NtStatus.Error) return true;
#endif
            return false;
        }
        public unsafe bool TryReadBytes(UIntPtr ptr, void* bytes, int count) {
#if KERNEL32
            if (ReadProcessMemory(pHandle, ptr, bytes, (UIntPtr)checked((ulong)count), IntPtr.Zero))
                return true;
#elif NTDLL
            if (NtReadVirtualMemory(pHandle, ptr, bytes, (uint)count, UIntPtr.Zero) < NtStatus.Error) return true;
#endif
            return false;
        }

        public byte ReadByte(UIntPtr ptr) {
            if (TryReadBytes(ptr, by, 1)) return by[0];
            return 0;
        }

        public int ReadInt(UIntPtr ptr) {
            if (TryReadBytes(ptr, by4, 4)) return BitConverter.ToInt32(by4, 0);
            return 0;
        }

        public float ReadFloat(UIntPtr ptr) {
            try {
                if (TryReadBytes(ptr, by4, 4)) return BitConverter.ToSingle(by4, 0);
            }
            catch { }
            return 0f;
        }

        public long ReadLong(UIntPtr ptr) {
            if (TryReadBytes(ptr, by16, 16)) return BitConverter.ToInt64(by16, 0);// TODO: 8 byte length?
            return 0L;
        }

        public UIntPtr ReadPointer(UIntPtr ptr) => (UIntPtr)ReadLong(ptr);

        public string ReadString(UIntPtr ptr, int length = 32, bool zeroTerminated = true) {
            byte[] array = new byte[length];
            if (TryReadBytes(ptr, array, length))
                return zeroTerminated ? Encoding.UTF8.GetString(array).Split('\0')[0] : Encoding.UTF8.GetString(array);
            return "";
        }

        public bool WriteBytes(UIntPtr address, byte[] value, uint size)
        {
            uint PAGE_EXECUTE_READWRITE = 0x0040;
            uint lpflOldProtect;
            VirtualProtectEx(pHandle, address, (int)size, PAGE_EXECUTE_READWRITE, out lpflOldProtect);
            return IsNtStatusSucess(NtWriteVirtualMemory(pHandle, address, value, size, UIntPtr.Zero));
        }


        public bool TryWriteBytes(UIntPtr ptr, byte[] data) {
#if KERNEL32
            return WriteProcessMemory(pHandle, ptr, data, (UIntPtr)checked((ulong)data.Length), IntPtr.Zero);
#elif NTDLL
            return IsNtStatusSucess(NtWriteVirtualMemory(pHandle, ptr, data, (uint)data.Length, UIntPtr.Zero));
#endif
        }

        public unsafe bool TryWriteBytes(UIntPtr ptr, void* data, int count) {
#if KERNEL32
            return WriteProcessMemory(pHandle, ptr, data, (UIntPtr)checked((ulong)count), IntPtr.Zero);
#elif NTDLL
            return IsNtStatusSucess(NtWriteVirtualMemory(pHandle, ptr, data, (uint)count, UIntPtr.Zero));
#endif
        }


        public unsafe bool TryReadStruct<T>(UIntPtr source, T* destination) where T : unmanaged {
            return TryReadBytes(source, destination, Marshal.SizeOf(typeof(T)));
        }

        public unsafe bool TryWriteStruct<T>(UIntPtr destination, T* source) where T : unmanaged {
            return TryWriteBytes(destination, source, Marshal.SizeOf(typeof(T)));
        }


        [DllImport("shell32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool IsUserAnAdmin();
        [DllImport("kernel32.dll")]
        static extern bool IsWow64Process(IntPtr hProcess, out bool lpSystemInfo);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32.dll")]
        public static extern int CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll")]
        static extern unsafe bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, void* lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        static extern unsafe bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, void* lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, UIntPtr lpBaseAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern NtStatus NtWriteVirtualMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, UIntPtr lpNumberOfBytesWritten);//ref uint
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern unsafe NtStatus NtWriteVirtualMemory(IntPtr hProcess, UIntPtr lpBaseAddress, void* lpBuffer, uint nSize, UIntPtr lpNumberOfBytesWritten);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern NtStatus NtReadVirtualMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, uint nSize, UIntPtr lpNumberOfBytesWritten);
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern unsafe NtStatus NtReadVirtualMemory(IntPtr hProcess, UIntPtr lpBaseAddress, void* lpBuffer, uint nSize, UIntPtr lpNumberOfBytesWritten);

        #region Datatypes
        public enum NtStatus : uint {
            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
        }
        #endregion

        static bool IsNtStatusSucess(NtStatus status) => status < NtStatus.Error;
    }
}
