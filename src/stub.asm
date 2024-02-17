.data

RopConfiguration STRUCT
    god_gadget             DQ 1
    gadget1             DQ 1
    gadget2             DQ 1
    gadget3             DQ 1
    gadget4             DQ 1
    gadget5             DQ 1
    gadget6             DQ 1
    gadget7             DQ 1
    gadget8             DQ 1
    gadget9             DQ 1

    ntprotectvm             DQ 1
    ntprotectvm_id             DQ 1
    processhandle             DQ 1
    memory_protections             DQ 1

    ntwaitobj             DQ 1
    ntwaitobj_id             DQ 1
    objhandle             DQ 1
    delay             DQ 1
    
    bencrypt             DQ 1
    bdecrypt             DQ 1
    key_handle             DQ 1 
    iv_len             DQ 1
    output_var             DQ 1
RopConfiguration ENDS

SectionInfo STRUCT
    section_address             DQ 1
    section_size             DQ 1
    original_protection             DQ 1
    output             DQ 1
SectionInfo ENDS

SectionsWrapper STRUCT
    base_address             DQ 1
    total_size             DQ 1
    iv_e             DQ 1
    iv_d             DQ 1
    n             DQ 1
    sec_size             DQ 1
    sections             DQ 1
SectionsWrapper ENDS


.code

    Fluctuate PROC
        mov r8, [rcx].RopConfiguration.key_handle     ; R8 contains key_handle*
        mov r13, [rcx].RopConfiguration.god_gadget    ; R13 will contain the address of GodGadget or 0 if it wasn't found
        mov r14, [rdx].SectionsWrapper.n              ; R14 contains the number of sections
        mov r15, [rdx].SectionsWrapper.sections       ; R15 contains the address of the current section in the loop
        
    loop_protect_1:  
        test r14, r14
        jz end_protect_1

        ; ----- NTProtectVirtualMemory
        push [r15].SectionInfo.output
        push 0
        push 0
        push 0
        push 0
        push [rcx].RopConfiguration.gadget6
        push [rcx].RopConfiguration.ntprotectvm

        test r13, r13
        jz loop_protect_1_regular

        push 0
        push [rcx].RopConfiguration.processhandle
        push [r15].SectionInfo.original_protection
        push [r15].SectionInfo.section_size
        push [rcx].RopConfiguration.processhandle
        push [r15].SectionInfo.section_address
        push [rcx].RopConfiguration.ntprotectvm_id
        push [rcx].RopConfiguration.god_gadget
        jmp loop_protect_1_next

    loop_protect_1_regular:
        push [rcx].RopConfiguration.ntprotectvm_id
        push [rcx].RopConfiguration.gadget9

        push 0
        push [rcx].RopConfiguration.processhandle
        push [rcx].RopConfiguration.gadget8

        push 0
        push 0
        push [r15].SectionInfo.original_protection
        push [rcx].RopConfiguration.gadget4

        push [r15].SectionInfo.section_size
        push [rcx].RopConfiguration.gadget3

        push 0
        push [r15].SectionInfo.section_address
        push [rcx].RopConfiguration.gadget2

        push [rcx].RopConfiguration.processhandle
        push [rcx].RopConfiguration.gadget1
        ; -----

    loop_protect_1_next:
        add r15, [rdx].SectionsWrapper.sec_size
        dec r14
        jmp loop_protect_1
    end_protect_1:

        ; ----- Stack alignment
        ; R10 will be set to 1 if the number of sections is odd
        mov r10, [rdx].SectionsWrapper.n
        and r10, 1
       
    crypt_1: 
        test r13, r13
        jz no_godgadget

        test r10, r10
        jz godgadget_even

        ; If GodGadget is present and N is odd, add the alignment gadget
        jmp alignment_gadget

        ; If GodGadget is present and N is even, skip the alignment gadget
        godgadget_even:
            jmp continue_crypt_1

        no_godgadget:
            ; If GodGadget is not present and N is even, skip the alignment gadget
            test r10, r10
            jz continue_crypt_1

            ; If GodGadget is not present and N is odd, add the alignment gadget

    alignment_gadget:
        push [rcx].RopConfiguration.gadget7
        ; -----

    continue_crypt_1:
        mov r14, [rdx].SectionsWrapper.base_address
        mov r15, [rdx].SectionsWrapper.total_size

        ; ----- BDecrypt
        push 0
        push 0
        push [rcx].RopConfiguration.output_var
        push [r15]
        push [r14]
        push [rcx].RopConfiguration.iv_len
        push [rdx].SectionsWrapper.iv_d
        push 0
        push 0
        push 0
        push 0
        push [rcx].RopConfiguration.gadget5
        push [rcx].RopConfiguration.bdecrypt

        test r13, r13
        jz crypt_1_regular

        push 0
        push 0
        push 0
        push [r15]
        push [r8]
        push [r14]
        push 0
        push [rcx].RopConfiguration.god_gadget
        jmp end_crypt_1

    crypt_1_regular:
        push 0
        push 0
        push 0
        push [rcx].RopConfiguration.gadget4

        push [r15]
        push [rcx].RopConfiguration.gadget3

        push 0
        push [r14]
        push [rcx].RopConfiguration.gadget2

        push [r8]
        push [rcx].RopConfiguration.gadget1
        ; -----

    end_crypt_1:

        ; ----- NtWaitForSingleObject
        push 0
        push 0
        push 0
        push 0
        push 0
        push [rcx].RopConfiguration.gadget6
        push [rcx].RopConfiguration.ntwaitobj
        
        test r13, r13
        jz wait_for_single_object_regular

        push 0
        push [rcx].RopConfiguration.objhandle
        push 0
        push [rcx].RopConfiguration.delay
        push [rcx].RopConfiguration.objhandle
        push 0
        push [rcx].RopConfiguration.ntwaitobj_id
        push [rcx].RopConfiguration.god_gadget
        jmp crypt_2

    wait_for_single_object_regular:
        push [rcx].RopConfiguration.ntwaitobj_id
        push [rcx].RopConfiguration.gadget9

        push 0
        push [rcx].RopConfiguration.objhandle
        push [rcx].RopConfiguration.gadget8
        
        push [rcx].RopConfiguration.delay
        push [rcx].RopConfiguration.gadget3

        push 0
        push 0
        push [rcx].RopConfiguration.gadget2

        push [rcx].RopConfiguration.objhandle
        push [rcx].RopConfiguration.gadget1
        ; -----

    crypt_2: 
        mov r14, [rdx].SectionsWrapper.base_address
        mov r15, [rdx].SectionsWrapper.total_size

        ; ----- BEncrypt
        push 0
        push 0
        push [rcx].RopConfiguration.output_var
        push [r15]
        push [r14]
        push [rcx].RopConfiguration.iv_len
        push [rdx].SectionsWrapper.iv_e
        push 0
        push [r14]
        push [r14]
        push [r8]
        push [rcx].RopConfiguration.gadget5
        push [rcx].RopConfiguration.bencrypt

        test r13, r13
        jz crypt_2_regular

        push 0
        push 0
        push 0
        push [r15]
        push [r8]
        push [r14]
        push 0
        push [rcx].RopConfiguration.god_gadget
        jmp end_crypt_2

    crypt_2_regular:
        push 0
        push 0
        push 0
        push [rcx].RopConfiguration.gadget4

        push[r15]
        push [rcx].RopConfiguration.gadget3

        push 0
        push [r14]
        push [rcx].RopConfiguration.gadget2

        push [r8]
        push [rcx].RopConfiguration.gadget1
        ; -----

    end_crypt_2:

        ; ----- NTProtectVirtualMemory 
        push [rcx].RopConfiguration.output_var
        push 0
        push 0
        push 0
        push 0
        push [rcx].RopConfiguration.gadget6
        push [rcx].RopConfiguration.ntprotectvm

        test r13, r13
        jz protect_2_regular

        push 0
        push [rcx].RopConfiguration.processhandle
        push [rcx].RopConfiguration.memory_protections
        push [rdx].SectionsWrapper.total_size
        push [rcx].RopConfiguration.processhandle
        push [rdx].SectionsWrapper.base_address
        push [rcx].RopConfiguration.ntprotectvm_id
        push [rcx].RopConfiguration.god_gadget
        jmp end_protect_2

    protect_2_regular:

        push [rcx].RopConfiguration.ntprotectvm_id
        push [rcx].RopConfiguration.gadget9

        push 0
        push [rcx].RopConfiguration.processhandle
        push [rcx].RopConfiguration.gadget8

        push 0
        push 0
        push [rcx].RopConfiguration.memory_protections
        push [rcx].RopConfiguration.gadget4

        push [rdx].SectionsWrapper.total_size
        push [rcx].RopConfiguration.gadget3

        push 0
        push [rdx].SectionsWrapper.base_address
        push [rcx].RopConfiguration.gadget2

        push [rcx].RopConfiguration.processhandle
        push [rcx].RopConfiguration.gadget1
        ; -----

    end_protect_2:
        ret
    Fluctuate ENDP

    SpoofAndCall PROC
        push rbp
        push rbx
        push rdi
        push rsi
        push r12
        push r13
        push r14
        push r15

        push 0              ; 16 byte stack alignment
        mov rax, rcx        ; Move unwinder::spoof_and_call's address to rax
        mov rcx, rdx        ; Set up parameters according to the calling convention
        mov rdx, r8
        mov r8, r9
        call qword ptr rax  ; Call unwinder::spoof_and_call

        pop r15
        pop r15
        pop r14
        pop r13
        pop r12
        pop rsi
        pop rdi
        pop rbx
        pop rbp
        ret
    SpoofAndCall ENDP

end