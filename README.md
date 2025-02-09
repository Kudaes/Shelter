# Shelter
Shelter is a completely weaponized sleep obfuscation technique that allows to fully encrypt your in-memory payload making an extensive use of ROP.

This crate comes with the following characteristics:
* AES-128 encryption.
* Whole PE encryption capability.
* Removal of execution permission during sleep time.
* No APC/HWBP/Timers used, exclusive use of ROP to achieve the obfuscation.
* Use of [Unwinder](https://github.com/Kudaes/Unwinder) to achieve call stack spoofing before executing the ROP chain.
* Different methods of execution to adapt to various circumstances.
* Other OPSEC considerations: [DInvoke_rs](https://github.com/Kudaes/DInvoke_rs), indirect syscalls, string literals encryption, etc.  
  

### Content
- [Usage](#usage)
- [Examples](#examples)
  - [fluctuate](#fluctuate)
  - [fluctuate_from_address](#fluctuate_from_address)
  - [fluctuate_from_pattern](#fluctuate_from_pattern)
- [Testing the module](#Testing-the-module)
- [TO-DO](#TO-DO)
<br>

---

## Usage

Import this crate into your project by adding the following line to your `cargo.toml`:

```rust
[dependencies]
shelter = "=0.1.1"
```
Then, compile your project on `--release` mode.

The main functionality of this crate has been wrapped in three functions:
* `fluctuate()` allows to encrypt either the current memory region or the whole PE. This function requires the PE's MZ bytes to be present in order to dynamically retrieve its base address.
* `fluctuate_from_address()` completely encrypts the PE. This function expects as input parameter the PE's base address.
* `fluctuate_from_pattern()` also completely encrypts the PE. This function expects as input parameter a custom set of two bytes to use to determine the PE's base address. These custom magic bytes replace the classic MZ pattern.

Whenever the whole PE is encrypted, the original sections' memory protections are stored in the heap in order to restore them afterwards. 

Shelter uses [NtWaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntwaitforsingleobject) to sleep. In addition to indicating how many seconds you want to sleep, you can also pass an event handle and signal it at any time to return before the timeout expires (using [SetEvent](https://learn.microsoft.com/es-es/windows/win32/api/synchapi/nf-synchapi-setevent) for example). Take into account that if your whole payload is encrypted (which is the whole point I guess), you will need an alternative way to signal the event in case that you have slept indefinitely.  
<br>


## Examples
### fluctuate 

The function expects the following parameters:
* A boolean value indicating whether encrypt the whole PE or just the current memory region. Passing `true` requires the MZ bytes to be present in memory.
* The number of seconds that the program will sleep for. If it is left to `None`, the timeout will be infinite, which means the execution will not return until the event passed to NtWaitForSingleObject is signaled.
* An event handle to be passed to NtWaitForSingleObject. This parameter can be `None`. The program will get stuck if you set this parameter and the timeout both to `None`.

```rust
let time_to_sleep = Some(10); // Sleep for 10 seconds
let _ = shelter::fluctuate(false, time_to_sleep, None); // Encrypt only the current memory region
```
```rust
let time_to_sleep = Some(10); // Sleep for 10 seconds
let _ = shelter::fluctuate(true, time_to_sleep, None); // Encrypt the whole PE
```
```rust
pub type CreateEventW = unsafe extern "system" fn (*const SECURITY_ATTRIBUTES, i32, i32, *const u16) -> HANDLE;

let k32 = dinvoke_rs::dinvoke::get_module_base_address("kernel32.dll"); 
let create_event: CreateEventW;
let event_handle: Option<HANDLE>;
dinvoke_rs::dinvoke::dynamic_invoke!(k32,"CreateEventW",create_event,event_handle,ptr::null_mut(),0,0,ptr::null());
let time_to_sleep = None; // Sleep indefinitely
let _ = shelter::fluctuate(true, time_to_sleep, event_handle); // Encrypt the whole PE until the event is signaled
```
<br>

### fluctuate_from_address

The function expects the following parameters:
* The number of seconds that the program will sleep for. If it is left to `None`, the timeout will be infinite, which means the execution will not return until the event passed to NtWaitForSingleObject is signaled.
* An event handle to be passed to NtWaitForSingleObject. This parameter can be `None.` The program will stuck if you set this parameter and the timeout both to `None`.
* The base address from which the PE is mapped. 

One way to use this function would be to manually map our payload with `Dinvoke_rs`. This way, the loader can send the payload its own base address, so then the payload can use it to obfuscate itself whenever is needed. This way, the loader can safely remove the PE's headers in order to achieve a certain level of stealthiness.

Loader example:

```rust
let payload: Vec<u8> = your_download_function();
let mut m = dinvoke_rs::manualmap::manually_map_module(payload.as_ptr(), true).unwrap();
println!("The dll is loaded at base address 0x{:x}", m.1);
let dll_exported_function = dinvoke::get_function_address(m.1, "run");

let run: unsafe extern "Rust" fn (usize) = std::mem::transmute(dll_exported_function);
run(m.1 as usize);
```

Payload example: 

```rust
#[no_mangle]
fn run(base_address: usize)
{
	...
	let time_to_sleep = Some(10); // Sleep for 10 seconds
	let _ = shelter::fluctuate_from_address(time_to_sleep, None, base_address); // Encrypt the entire PE from this specific base address
	...
}
 ```
<br>

### fluctuate_from_pattern

The function expects the following parameters:
* The number of seconds that the program will sleep for. If it is left to `None`, the timeout will be infinite, which means the execution will not return until the event passed to NtWaitForSingleObject is signaled.
* An event handle to be passed to NtWaitForSingleObject. This parameter can be `None`. The program will stuck if you set this parameter and the timeout both to `None`.
* A `[u8;2]` array containig custom magic bytes to look for in order to obtain the PE's base address. 

The point of creating this function is to allow the loader to remove PE's header and other signatures, including the classic MZ bytes. This way, those bytes can be replaced by a custom pattern that Shelter will look for in order to retrieve the PE's base address.

```rust
let time_to_sleep = Some(10); // Sleep for 10 seconds
let pattern = [0x29,0x07];
let _ = shelter::fluctuate_from_pattern(time_to_sleep, None, pattern); // Encrypt the whole PE using custom pattern as magic bytes
```  
    
<br>

## Testing the module

In order to test the implementation of the technique, mainly [PE-sieve](https://github.com/hasherezade/pe-sieve) has been used. By default, PE-sieve looks for implants within executable memory regions, which means that even obfuscating exclusively the current memory region (`.text`) is enough to avoid detections:

![Current memory region obfuscation.](/images/current_PE1.PNG "Current memory region obfuscation")
![Current memory region obfuscation (Process Hacker).](/images/current_PE1.2.PNG "Current memory region obfuscation (Process Hacker)")

Notice that, since we are using `Unwinder`, the call stack is spoofed and therefore the flag `/threads` does not detect the mapped dll neither.

Now, PE-sieve allows to inspect non executable memory regions as well by using the `/data` flag. According to the [official documentation of the tool](https://github.com/hasherezade/pe-sieve/wiki/4.4.-Scan-non-executable-memory-(data)), this flag set to `always` can "produce a lot of noise/false positives". Despite that, we decided to use it in order to check the effectiveness of the whole PE encryption capability, since it allows to hide PE's data regions that could contain indicators of the presence of a in-memory implant.

![Current memory region obfuscation detected by PE-sieve.](/images/current_PE2.PNG "Current memory region obfuscation detected by PE-sieve")
![Entire PE obfuscation stays undetected.](/images/entire_PE.PNG "Entire PE obfuscation stays undetected")

As it can be seen, in the first picture it is shown how obfuscating just the `.text` section is not enough when PE-sieve scans non executable memory pages, since some regions could contain strings that reveal the presence of a DLL (MZ, DOS header, section names, etc.). On the other hand, the second image shows how this issue can be solved by using Shelter's whole PE obfuscation mechanism. In any case and as stated in the PE-sieve's wiki, this option leads to tons of false positive since the mere presence in the heap of strings like ".data" or "rdata" already warns of possible implanted PE, despite it is not able to dump anything from the memory (since there is not any real PE content in that region).

Finally, PE-sieve has a fairly new option to detect the presence of obfuscated implants by looking for high entropy memory regions. This option (`/obfusc`) in combination with `/data` is able to detect the presence of the payload due to the high entropy of the memory region that contains it (although it can't retrieve the PE since it's fully encrypted):

![Entire PE obfuscation detection.](/images/high_entropy.PNG "Entire PE obfuscation detection")
![Entire PE obfuscation (Process Hacker).](/images/high_entropy2.PNG "Entire PE obfuscation (Process Hacker)")
<br>

## TO-DO

Although Shelter is ready to use and it has been developed with OPSEC in mind, there are still some enhancements that will be added in the nearby future:
* Reduce entropy when the whole PE is encrypted.
* Replace `BCryptEncrypt`/`BCryptDecrypt` with the corresponding Nt function.
* Add some randomness to the gadget selection process.

## Previous work
* [Gargoyle](https://github.com/JLospinoso/gargoyle)
* [Ekko](https://github.com/Cracked5pider/Ekko)
* [Cronos](https://github.com/Idov31/Cronos)
