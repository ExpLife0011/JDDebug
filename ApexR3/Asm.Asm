.DATA
.CODE
GetPeb PROC
    mov rax,qword ptr gs:[60h]
    ret
GetPeb ENDP
END