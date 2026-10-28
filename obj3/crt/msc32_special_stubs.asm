; msc32_special_stubs.asm - Special symbol stubs for dcc32 + MSVC Win32
; Assemble: ml /c /coff msc32_special_stubs.asm
;
; ?buff@?1??gai_strerrorA@@9@9 : static local char[1024] in gai_strerrorA
;   This is a C++ mangled name — cannot use C language model, must be raw.

.386
.model flat

.data

; gai_strerrorA's static local buffer: char buff[1024]
; Use raw PUBLIC to avoid C-decoration of mangled name
PUBLIC ?buff@?1??gai_strerrorA@@9@9
?buff@?1??gai_strerrorA@@9@9 db 1024 dup(0)

.code

END
