# RefinedPool

**Evading Elastic EDR call stack signatures through dynamic code cave injection**

RefinedPool is an enhancement of [LibTPLoadLib](https://github.com/AlmondOffSec/LibTPLoadLib) by [@AlmondOffSec](https://github.com/AlmondOffSec), which uses call gadgets to break the [call stack signature used by Elastic EDR](https://github.com/elastic/protections-artifacts/blob/6e9ee22c5a7f57b85b0cb063adba9a3c72eca348/behavior/rules/windows/defense_evasion_library_loaded_via_a_callback_function.toml) on proxying module loads via Windows Thread Pool API.

### Original Technique

The original **LibTPLoadLib** technique (detailed in [this blogpost](https://offsec.almond.consulting/evading-elastic-callstack-signatures.html)) works by:
- Using Thread Pool callbacks to proxy `LoadLibraryA` calls
- Leveraging a call gadget (`call r10; add rsp, 0x28; ret`) to remove the callback function from the call stack

![diagram](https://offsec.almond.consulting/images/evading-elastic-callstack-signatures/callback2_0_diagram.png)

- This breaks Elastic's detection pattern that looks for suspicious call stacks when loading libraries

**The original approach required:**
- Loading a specific hardcoded DLL (`dsdmo_10.0.26100.1882.dll`) containing the gadget
- The DLL had to be manually placed at `C:\dsdmo_10.0.26100.1882.dll`
- This creates a circular dependency: loading a suspicious DLL to evade detection of loading DLLs

## "Innovation"

The need for external hardcoded DLLs was eliminated by implementing **dynamic code cave injection**.

Instead of searching for pre-existing gadgets in hardcoded DLLs, RefinedPool:

1. **Enumerates loaded modules** in the current process
2. **Locates code caves** within executable sections, specifically:
   - Searches inside existing function boundaries using the Exception Directory (`.pdata` / `RUNTIME_FUNCTION` table)
   - Looks for continuous sequences of null bytes or INT3 instructions (`0xCC`)
   - Ensures the cave is at least 10 bytes to fit the gadget
3. **Writes the gadget dynamically** into the discovered code cave:
   ```asm
   41 FF D2        ; call r10
   33 C0           ; xor eax, eax
   48 83 C4 28     ; add rsp, 0x28
   C3              ; ret
   ```
4. **Uses the injected gadget** for the Thread Pool callback, just like the original technique

### Advantages

- **No external DLL dependencies**: Works with modules already loaded in memory
- **Stealthier**: No suspicious DLL load operations that could trigger alerts
- **More practical**: Doesn't require specific Windows versions or pre-staged files
- **Dynamic adaptation**: Searches across multiple candidate modules automatically
- **Function-aware**: Preferentially places gadgets within legitimate function boundaries for "better stealth"

## Call Stack Result

![result](https://i.imgur.com/sluvimD.png)

![result_shellcode_execution](https://i.imgur.com/OPocl8J.png)

---

### Module Exclusion List

To avoid critical system modules, RefinedPool excludes:
- `ntdll.dll`
- `kernel32.dll`
- `kernelbase.dll`

## Methods

The methods can be easily alternated in "loadlib.c".

1. **WriteGadget** (primary method):
   - Combines code cave detection with dynamic gadget injection
   - Uses `FindCodeCaveInFunction` to locate suitable memory space
   - Writes the 10-byte gadget sequence directly into discovered code caves
   - Handles memory protection changes (VirtualProtect) automatically

2. **FindCallGadget** (original method):
   - Searches for pre-existing gadget patterns in loaded modules
   - Scans candidate DLLs for the byte sequence: `41 FF D2 ... 48 83 C4 28 C3`
   - Kept for compatibility and fallback scenarios
   - Can be used as alternative when code cave injection is not desired

## Credits & References

### Original Work
- **LibTPLoadLib** by [@AlmondOffSec](https://github.com/AlmondOffSec)
  - Repository: https://github.com/AlmondOffSec/LibTPLoadLib
  - Blog: https://offsec.almond.consulting/evading-elastic-callstack-signatures.html
  - License: BSD 3-Clause License (see [tploadlib.c](https://github.com/AlmondOffSec/LibTPLoadLib/blob/main/src/tploadlib.c))

### Inspiration & Research
- [Elastic EDR detection rule](https://github.com/elastic/protections-artifacts/blob/6e9ee22c5a7f57b85b0cb063adba9a3c72eca348/behavior/rules/windows/defense_evasion_library_loaded_via_a_callback_function.toml) - The signature this technique bypasses
- [@rasta-mouse's LibTP](https://github.com/rasta-mouse/LibTP) - Format inspiration for the original project
- [Crystal Palace](https://tradecraftgarden.org/crystalpalace.html) - Shared library framework used in the original
- [Carregamento por Proxy](https://vith0r.gitbook.io/public/malware-dev/posts/stack/carregamento-por-proxy) - My research on proxy loading techniques
- [Return Address Spoofing](https://vith0r.gitbook.io/public/malware-dev/posts/stack/return-address-spoofing) - My research on call stack manipulation

## License

This project respects the original BSD 3-Clause License from LibTPLoadLib. See the copyright notice in [tploadlib.c](https://github.com/AlmondOffSec/LibTPLoadLib/blob/main/src/tploadlib.c) for the original license terms.

## Acknowledgments

Special thanks to [@AlmondOffSec](https://github.com/AlmondOffSec) / [@SAERXCIT](https://github.com/SAERXCIT) for the original research and implementation that made this enhancement possible.
