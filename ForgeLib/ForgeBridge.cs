﻿using ForgeLib.Halo3;
using net.r_eg.DllExport;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Linq;

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

                // Static Address
                ptrAddress = (UIntPtr)0x7FF47E27495C;
                objectPtr = ptrAddress + 0x1D8;
                objectCount = ptrAddress + 0xFC;

                Console.WriteLine($"[SUCCESS] Using hardcoded pointer: {ptrAddress}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Exception in FindPointer(): {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }



        static void GetH3Pointer()
        {
            try
            {
                Console.WriteLine("[DEBUG] Entering GetH3Pointer()...");

                // Static address instead of pointer
                ptrAddress = (UIntPtr)0x7FF47E27495C;
                objectPtr = ptrAddress + 0x1D8;
                objectCount = ptrAddress + 0xFC;

                Console.WriteLine($"[SUCCESS] Using hardcoded address: {ptrAddress}");

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