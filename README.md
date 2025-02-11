# MJOLNIR
Mjolnir is a Blender tool for importing/exporting/building Halo 3 Forge maps in Master Chief Collection.

Working as of halo3.dll build 1.3385.0.0 

I am not the creator of this tool. This tool was originally built off of the Halo Reach Mjolnir tool. ExhibitMark created this version for Halo 3. I am just restoring the 
source code for the newest version of MCC and adding on to it. 

### Brief Tutorial
https://www.youtube.com/watch?v=bnRqn_kbU0w

**Features**
- Import / Export Objects to and from game
- Utilize channels larger than 10 and any spawn time between 0-255
- Spawn objects in an array
- Prefabs
- "Toggle Physics". Pressing this will enable the game to spawn all objects as phased automatically
- "Optimize Selected". When importing a prefab if you select those objects and any default map pieces available it will attempt to replace the imported ones with the default one.

*Limitations*
- Only works on Sandbox
- Halo 3 is finicky and crashes if you do anything wrong. Save often
- Some objects aren't implemented but it will still be named and use a null object to represent it
- After about 3 exports the game will not show all your objects and usually remove your weapon. All is fine, just save a backup and leave the game and load the map back up.
- DONT MOVE AROUND THE OBJECT ORDER IN THE OUTLINER ON THE RIGHT IT WILL CRASH THE GAME ON EXPORT.

**REQUIREMENTS**
- Blender 3.2 or greater
- Halo: MCC with anticheat disabled (this has only been tested on the Steam version, there's no reason it shouldn't work on the Microsoft Store version but it's untested)

**GETTING STARTED**
1. Download the zip of the current release build.
2. Extract all the contents of the zip to the same folder. It shouldn't matter what folder just keep all the files together.
3. Follow the video for basic usage information.

**ISSUES**
- TogglePhysics() function not restored yet. 

**Plans**
I plan to recreate this tool in C++ so it will be more efficient. I am also planning to make it work on all maps with their models and assets. If you need help with anything
hit me up on discord. Username is pownin.

**CREDIT**
- Waffle1434
- ExhibitMark
- Pownin
- Bytrl
