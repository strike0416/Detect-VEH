# Detect VectoredExceptionHandler(VEH)
Detect VectoredExceptionHandler(VEH) by look up <b>LdrpVectorHandlerList</b>.<br>
tested on Windows 11 ver 23H2

# PoC
To detect VectoredExceptionHandler, you need to analyze the <b>RtlAddVectoredExceptionHandler</b>.
Using ida, you can see that VectoredExceptionHandler is stored in a structure named <b>LdrpVectorHandlerList</b> as shown in the picture below.
You can obtain the LdrpVectorHandlerList value by performing a pattern scan for `83 E0 3F 48 8D 3D`.
<img src="imgs/LdrpVectorHandlerList_ida.png">

The struct of the handler list is as follows.
```cpp
typedef struct _VECTORED_HANDLER_LIST
{
	PVOID mutex_exception;
	PVECTORED_HANDLER_ENTRY first_exception_handler;
	PVECTORED_HANDLER_ENTRY last_exception_handler;
	PVOID mutex_continue;
	PVECTORED_HANDLER_ENTRY first_continue_handler;
	PVECTORED_HANDLER_ENTRY last_continue_handler;
} VECTORED_HANDLER_LIST, *PVECTORED_HANDLER_LIST;
```

The handlers are implemented as a circular linked-list structure, and when no VectoredExceptionHandler is registered, the value at `LdrpVectorHandlerList + 0x8` is stored in `first_exception_handler`.
The structure of the handler node is as follows.
```cpp
typedef struct _VECTORED_HANDLER_ENTRY
{
	LIST_ENTRY entry;
	PVOID refs;
	PVOID unknown;
	PVECTORED_EXCEPTION_HANDLER encrypted_handler;
} VECTORED_HANDLER_ENTRY, *PVECTORED_HANDLER_ENTRY;
```

Since the handlers are encrypted with <b>EncodePointer</b>, you need to retrieve the <b>Process Cookie</b> and decode them.
The following shows the structure of the <b>RtlDecodePointer</b>, and by examining it, you can see that the Process Cookie is cached.
<img src="imgs/RtlDecodePointer_ida.png">

A helper function for retrieving the cached Process Cookie has also been implemented in the source code. Refer to this function as needed.

After obtaining the Process Cookie, you can compute the decoded handler value by applying a `ROR` operation.

# References
https://dimitrifourny.github.io/2020/06/11/dumping-veh-win10.html
