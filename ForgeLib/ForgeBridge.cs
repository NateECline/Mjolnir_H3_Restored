using ForgeLib.Halo3;
using net.r_eg.DllExport;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Linq;
using ForgeLib;


namespace ForgeLib
{


    public enum Game : byte
    {
        None,
        HaloReach,
        Halo3,
    }

    public enum Map
    {
        None,
        // Halo 3
        Construct,
        Epitaph,
        Guardian,
        HighGround,
        Isolation,
        LastResort,
        Narrows,
        Sandtrap,
        Snowbound,
        ThePit,
        Valhalla,
        Foundry,
        RatsNest,
        Standoff,
        Avalanche,
        Blackout,
        GhostTown,
        ColdStorage,
        Assembly,
        Orbital,
        Sandbox,
        Citadel,
        Heretic,
        Longshore
    }


    public static class ForgeBridge
    {
        public const int H3_maxObjects = 640;
        public static Game currentGame;
        public static ProcessMemory memory = new ProcessMemory();
        public static Map currentMap;
        public static Dictionary<int, MccForgeObject> forgeObjects = new Dictionary<int, MccForgeObject>();
        static UIntPtr objectPtr;
        static UIntPtr objectCount;
        static UIntPtr ptrAddress;
        static UIntPtr mccAddress;
        static UIntPtr m_physics_patch;

        static H3_MapVariant h3_mvar = new H3_MapVariant();

        static readonly byte?[] AOB_PATTERN = { null, null, null, null, 0x49, 0x8B, 0xE8, 0xF3, 0x0F, 0x10, 0x25 };


        [DllExport("GetDllVersion", CallingConvention = CallingConvention.Cdecl)]
        public static int GetDllVersion() => 4;

        [DllExport(CallingConvention = CallingConvention.Cdecl)]
        public static bool TrySetConnect(bool connect)
        {
            if (connect)
            {
                if (memory.Connected) return true;

                Process[] processes = null;
                foreach (string procName in new string[] { "MCC-Win64-Shipping", "MCCWinStore-Win64-Shipping" })
                {
                    processes = Process.GetProcessesByName(procName);
                    if (processes.Length > 0) goto FoundProcess;
                }

                lastError = "Failed to find Master Chief Collection process.";
                return false;

            FoundProcess:
                mccAddress = (UIntPtr)(long)processes[0].MainModule.BaseAddress;
                if (!memory.OpenProcess(processes[0].Id))
                {
                    lastError += "Failed to connect to process.\n";
                    return false;
                }
            }
            else
            {
                try
                {
                    memory.CloseProcess();
                }
                catch
                {
                    lastError = "Failed to close process.";
                    return false;
                }
            }

            return true;
        }

        public static string lastError;
        [DllExport(CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.LPWStr)]
        public static string GetLastError() => lastError;

        [DllExport(CallingConvention = CallingConvention.Cdecl)]
        public static int GetObjectCount() => forgeObjects.Count;

        [DllExport(CallingConvention = CallingConvention.Cdecl)]
        public static unsafe H3_ForgeObject* GetObjectPtr(int i)
        {
            return MccForgeObject.GetPointer(i);
        }

        [DllExport(CallingConvention = CallingConvention.Cdecl)]
        static void FindPointer(UIntPtr halo3Base)
        {
            try
            {
                Console.WriteLine("[DEBUG] Entering FindPointer()...");

                // Find the MCC process
                Process[] processes = Process.GetProcessesByName("MCC-Win64-Shipping");
                if (processes.Length == 0)
                {
                    Console.WriteLine("[ERROR] MCC process not found!");
                    return;
                }

                int processId = processes[0].Id;
                Console.WriteLine($"[DEBUG] Found MCC process ID: {processId}");

                // Initialize memory scanner
                MemoryScanner scanner = new MemoryScanner(processId);
                IntPtr foundAddress = scanner.FindPattern("halo3.dll", AOB_PATTERN);

                if (foundAddress == IntPtr.Zero)
                {
                    Console.WriteLine("[ERROR] AOB scan failed. No matches found.");
                    return;
                }

                Console.WriteLine($"[SUCCESS] AOB match found at: 0x{foundAddress.ToInt64():X}");

                // Read the offset from the found address
                byte[] valueBuffer = new byte[4];
                if (!scanner.ReadMemory(foundAddress, valueBuffer))
                {
                    Console.WriteLine("[ERROR] Failed to read offset!");
                    return;
                }

                int offset = BitConverter.ToInt32(valueBuffer, 0);
                Console.WriteLine($"[SUCCESS] Read offset: {offset:X}");

                // Extract the TLS index
                byte[] indexBuffer = new byte[1];
                if (!scanner.ReadMemory(foundAddress + offset + 4, indexBuffer))
                {
                    Console.WriteLine("[ERROR] Failed to extract TLS index!");
                    return;
                }

                int extractedTLSIndex = indexBuffer[0];
                Console.WriteLine($"[SUCCESS] Extracted TLS index: {extractedTLSIndex}");

                // Find TLS Address
                IntPtr tlsAddress = FindTLSAddress(processes[0], scanner, extractedTLSIndex);
                if (tlsAddress == IntPtr.Zero)
                {
                    Console.WriteLine("[ERROR] Failed to retrieve TLS address.");
                    return;
                }

                Console.WriteLine($"[SUCCESS] Found valid TLS address: 0x{tlsAddress.ToInt64():X}");

                // **Apply Offset (+120)**
                IntPtr finalPointer = tlsAddress + 120;
                ptrAddress = new UIntPtr((ulong)finalPointer.ToInt64());

                objectPtr = ptrAddress + 0x1D8;
                objectCount = ptrAddress + 0xFC;

                Console.WriteLine($"[SUCCESS] Final Pointer: 0x{ptrAddress.ToUInt64():X}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Exception in FindPointer(): {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }


        static IntPtr FindTLSAddress(Process targetProcess, MemoryScanner scanner, int index)
        {
            IntPtr result = IntPtr.Zero;
            int tlsSlotIndex = index;

            foreach (ProcessThread thread in targetProcess.Threads)
            {
                IntPtr hThread = MemoryScanner.OpenThread(0x0040 | 0x0800, false, (uint)thread.Id);
                if (hThread == IntPtr.Zero)
                {
                    Console.WriteLine($"[ERROR] Failed to open thread {thread.Id}");
                    continue;
                }

                // Query thread information
                MemoryScanner.THREAD_BASIC_INFORMATION tbi = new MemoryScanner.THREAD_BASIC_INFORMATION();
                int status = MemoryScanner.NtQueryInformationThread(hThread, 0, out tbi, Marshal.SizeOf<MemoryScanner.THREAD_BASIC_INFORMATION>(), IntPtr.Zero);

                if (status != 0)
                {
                    Console.WriteLine($"[ERROR] Failed to get TEB for thread {thread.Id}. Status: {status}");
                    continue;
                }

                // Read TLS pointer from TEB (offset 0x58)
                byte[] tlsPointerBuffer = new byte[8];
                if (!scanner.ReadMemory(tbi.TebBaseAddress + 0x58, tlsPointerBuffer))
                {
                    Console.WriteLine($"[ERROR] Failed to read TLS pointer for thread {thread.Id}");
                    continue;
                }

                IntPtr tlsPointer = (IntPtr)BitConverter.ToInt64(tlsPointerBuffer, 0);

                // Read module-specific TLS slot
                byte[] tlsBuffer = new byte[8];
                if (!scanner.ReadMemory(tlsPointer + tlsSlotIndex * IntPtr.Size, tlsBuffer))
                {
                    Console.WriteLine($"[ERROR] Failed to read module TLS slot for thread {thread.Id}");
                    continue;
                }

                IntPtr moduleTlsPointer = (IntPtr)BitConverter.ToInt64(tlsBuffer, 0);

                // Read final address at (moduleTlsPointer + 0x20)
                if (!scanner.ReadMemory(moduleTlsPointer + 0x20, tlsBuffer))
                {
                    Console.WriteLine($"[ERROR] Failed to read final pointer for thread {thread.Id}");
                    continue;
                }

                IntPtr finalPointer = (IntPtr)BitConverter.ToInt64(tlsBuffer, 0);

                if (finalPointer.ToInt64().ToString("X").StartsWith("7F"))
                {
                    Console.WriteLine($"[SUCCESS] Found valid TLS address: 0x{finalPointer.ToInt64():X}");
                    result = finalPointer;
                    break;
                }
            }

            if (result == IntPtr.Zero)
            {
                Console.WriteLine("[ERROR] Failed to locate TLS address.");
            }

            return result;
        }


        static void GetH3Pointer()
        {
            try
            {
                Console.WriteLine("[DEBUG] Entering GetH3Pointer()...");

                if (ptrAddress == UIntPtr.Zero)
                {
                    Console.WriteLine("[ERROR] ptrAddress is zero! Run FindPointer() first.");
                    return;
                }

                Console.WriteLine($"[SUCCESS] Using dynamically found address: {ptrAddress}");

                unsafe
                {
                    fixed (H3_MapVariant* mvarPtr = &h3_mvar)
                    {
                        Console.WriteLine("[DEBUG] Attempting to read MVAR structure...");

                        if (!memory.TryReadStruct(ptrAddress, mvarPtr))
                        {
                            Console.WriteLine("[ERROR] Failed to read MVAR struct at ptrAddress!");
                            return;
                        }

                        Console.WriteLine("[SUCCESS] Successfully read MVAR struct.");
                        Console.WriteLine("BRIDGE LOGS");
                        Console.WriteLine("====================\n");
                        Console.WriteLine($"Reading Halo 3 MVAR: {h3_mvar.data.DisplayName}");
                        Console.WriteLine($"Description: {h3_mvar.data.Description}");
                        Console.WriteLine($"Author: {h3_mvar.data.Author}");

                        H3_ForgeObject* objPtr = h3_mvar.GetForgeObjects();
                        for (int i = 0; i < 640; i++)
                        {
                            H3_ForgeObject obj = *objPtr;
                            objPtr++;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Exception in GetH3Pointer(): {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }


        [DllExport(CallingConvention = CallingConvention.Cdecl)]
        public static void TogglePhysics()
        {
            if (memory.TryGetModuleBaseAddress("halo3.dll", out UIntPtr halo3Base))
            {
                m_physics_patch = halo3Base + 0xBB65C;
                byte currentState = memory.ReadByte(m_physics_patch);
                byte[] next = new byte[1];
                if (currentState == 12)
                {
                    next[0] = 188;
                    memory.WriteBytes(m_physics_patch, next, (uint)next.Length);
                }
                else if (currentState == 188)
                {
                    next[0] = 12;
                    memory.WriteBytes(m_physics_patch, next, (uint)next.Length);
                }
            }
        }

        [DllExport(CallingConvention = CallingConvention.Cdecl)]
        public static void ReadMemory()
        {
            GetH3Pointer();
        }

        [DllExport(CallingConvention = CallingConvention.Cdecl)]
        public static void WriteMemory(string hex, int index)
        {
            if (!memory.Connected) return;
            byte[] outArr = StringToByteArray(hex);
            UIntPtr ptr = objectPtr + (index * H3_ForgeObject.size);
            memory.TryWriteBytes(ptr, outArr);

        }

        [DllExport(CallingConvention = CallingConvention.Cdecl)]
        public static void WriteCount(short count)
        {
            if (!memory.Connected) return;
            byte[] countArray = BitConverter.GetBytes(count);
            memory.TryWriteBytes(objectCount, countArray);

        }

        [DllExport(CallingConvention = CallingConvention.Cdecl)]
        public static void ClearObjectList() => forgeObjects.Clear();


        [DllExport(CallingConvention = CallingConvention.Cdecl)]
        public static unsafe H3_MapVariant* GetH3_MVAR_Ptr()
        {
            h3_mvar = default;
            GetH3Pointer();
            fixed (H3_MapVariant* ptr = &h3_mvar) return ptr;
        }

        [DllExport(CallingConvention = CallingConvention.Cdecl)]
        public static Game GetGame() => currentGame;

        [DllExport(CallingConvention = CallingConvention.Cdecl)]
        public static H3_MapVariant GetH3_MVAR() => h3_mvar;

        static public string ToReadableByteArray(byte[] bytes)
        {
            return string.Join(", ", bytes);
        }

        public static byte[] StringToByteArray(string hexString)
        {
            return Enumerable.Range(0, hexString.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hexString.Substring(x, 2), 16))
                             .ToArray();
        }

    }
}