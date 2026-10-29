unit TestOpenSSLCallbackABI;

interface

uses System.SysUtils, Winapi.Windows, DUnitX.TestFramework, Winapi.WinSock2, libOpenSSL3;

{$IF DEFINED(C_COMPILER_BCC32C) OR DEFINED(C_COMPILER_MSC_32)}
{$DEFINE ABI_CDECL}
{$IFEND}

type
  [TestFixture]
  TTestCallbackABI = class
  public
    [TearDown] procedure ClearErrors;
{$IFDEF ABI_LAYOUT_PROBE}
    [Test] procedure CRecordLayoutOracle;
    [Test] procedure SignalCallbackABI;
{$ENDIF}
    [Test] procedure CRTStatRecordFields;
    [Test] procedure MutableExDataDuplication;
    [Test] procedure BIOMethodCallbackRoundTrip;
    [Test] procedure BIOExtendedObserver;
    [Test] procedure AsyncCallbackOutputs;
    [Test] procedure ProviderDispatchRecords;
    [Test] procedure PublicRecordFields;
    [Test] procedure RandMethodCallbacks;
    [Test] procedure EncryptedPEMPasswordCallback;
    [Test] procedure LegacyAlgorithmCallbacks;
  end;

implementation

procedure TTestCallbackABI.ClearErrors;
begin
  ERR_clear_error;
end;

{$IFDEF ABI_LAYOUT_PROBE}
{$L record_layout_probe.obj}
function openssl_record_layout(RecordID, FieldID: Cardinal): Cardinal;
{$IFDEF ABI_CDECL}cdecl;{$ENDIF}
{$IFDEF C_COMPILER_BORLAND_32}external;{$ELSE}external name EXTERNAL_NAME_PREFIX + 'openssl_record_layout';{$ENDIF}
procedure openssl_invoke_signal(Handler: C_signal_func);
{$IFDEF ABI_CDECL}cdecl;{$ENDIF}
{$IFDEF C_COMPILER_BORLAND_32}external;{$ELSE}external name EXTERNAL_NAME_PREFIX + 'openssl_invoke_signal';{$ENDIF}

procedure Layout(ID: Cardinal; Size: Integer; const Offsets: array of NativeUInt);
var I: Integer;
begin
  Assert.AreEqual(Cardinal(Size), openssl_record_layout(ID, 0), Format('C sizeof record %d', [ID]));
  for I := 0 to High(Offsets) do
    Assert.AreEqual(Cardinal(Offsets[I]), openssl_record_layout(ID, I + 1),
      Format('C offsetof record %d field %d', [ID, I + 1]));
end;

procedure TTestCallbackABI.CRecordLayoutOracle;
var
  A: ASN1_TYPE; B: ASN1_ITEM; C: BUF_MEM; D: ASN1_STRING_TABLE;
  E: X509_ALGOR; F: RSA_PSS_PARAMS; G: RSA_OAEP_PARAMS; H: RAND_METHOD;
  J: OSSL_DISPATCH; K: OSSL_ITEM; L: OSSL_ALGORITHM; M: OSSL_PARAM; N: CRYPTO_EX_DATA;
begin
  Layout(1, SizeOf(A), [NativeUInt(@A.type_) - NativeUInt(@A), NativeUInt(@A.value) - NativeUInt(@A)]);
  Layout(2, SizeOf(B), [NativeUInt(@B.itype) - NativeUInt(@B), NativeUInt(@B.utype) - NativeUInt(@B),
    NativeUInt(@B.templates) - NativeUInt(@B), NativeUInt(@B.tcount) - NativeUInt(@B),
    NativeUInt(@B.funcs) - NativeUInt(@B), NativeUInt(@B.size) - NativeUInt(@B), NativeUInt(@B.sname) - NativeUInt(@B)]);
  Layout(3, SizeOf(C), [NativeUInt(@C.length) - NativeUInt(@C), NativeUInt(@C.data) - NativeUInt(@C),
    NativeUInt(@C.max) - NativeUInt(@C), NativeUInt(@C.flags) - NativeUInt(@C)]);
  Layout(4, SizeOf(D), [NativeUInt(@D.nid) - NativeUInt(@D), NativeUInt(@D.minsize) - NativeUInt(@D),
    NativeUInt(@D.maxsize) - NativeUInt(@D), NativeUInt(@D.mask) - NativeUInt(@D), NativeUInt(@D.flags) - NativeUInt(@D)]);
  Layout(5, SizeOf(E), [NativeUInt(@E.algorithm) - NativeUInt(@E), NativeUInt(@E.parameter) - NativeUInt(@E)]);
  Layout(6, SizeOf(F), [NativeUInt(@F.hashAlgorithm) - NativeUInt(@F), NativeUInt(@F.maskGenAlgorithm) - NativeUInt(@F),
    NativeUInt(@F.saltLength) - NativeUInt(@F), NativeUInt(@F.trailerField) - NativeUInt(@F), NativeUInt(@F.maskHash) - NativeUInt(@F)]);
  Layout(7, SizeOf(G), [NativeUInt(@G.hashFunc) - NativeUInt(@G), NativeUInt(@G.maskGenFunc) - NativeUInt(@G),
    NativeUInt(@G.pSourceFunc) - NativeUInt(@G), NativeUInt(@G.maskHash) - NativeUInt(@G)]);
  // @@ measures a procedural field's storage slot instead of its code address.
  Layout(8, SizeOf(H), [NativeUInt(@@H.seed) - NativeUInt(@H), NativeUInt(@@H.bytes) - NativeUInt(@H),
    NativeUInt(@@H.cleanup) - NativeUInt(@H), NativeUInt(@@H.add) - NativeUInt(@H),
    NativeUInt(@@H.pseudorand) - NativeUInt(@H), NativeUInt(@@H.status) - NativeUInt(@H)]);
  Layout(9, SizeOf(J), [NativeUInt(@J.function_id) - NativeUInt(@J), NativeUInt(@J.function_) - NativeUInt(@J)]);
  Layout(10, SizeOf(K), [NativeUInt(@K.id) - NativeUInt(@K), NativeUInt(@K.Ptr) - NativeUInt(@K)]);
  Layout(11, SizeOf(L), [NativeUInt(@L.algorithm_names) - NativeUInt(@L), NativeUInt(@L.property_definition) - NativeUInt(@L),
    NativeUInt(@L.implementation_) - NativeUInt(@L), NativeUInt(@L.algorithm_description) - NativeUInt(@L)]);
  Layout(12, SizeOf(M), [NativeUInt(@M.key) - NativeUInt(@M), NativeUInt(@M.data_type) - NativeUInt(@M),
    NativeUInt(@M.data) - NativeUInt(@M), NativeUInt(@M.data_size) - NativeUInt(@M), NativeUInt(@M.return_size) - NativeUInt(@M)]);
  Layout(13, SizeOf(N), [NativeUInt(@N.ctx) - NativeUInt(@N), NativeUInt(@N.sk) - NativeUInt(@N)]);
end;

var SignalValue: Integer;
procedure SignalHandler(Sig: Integer); cdecl;
begin
  SignalValue := Sig;
end;

procedure TTestCallbackABI.SignalCallbackABI;
begin
  SignalValue := 0;
  openssl_invoke_signal(SignalHandler);
  Assert.AreEqual(-17, SignalValue);
end;
{$ENDIF}

{$IF DEFINED(C_COMPILER_MSC_32) OR DEFINED(C_COMPILER_MSC_64)}
function ReadUCRTStat(Path: PAnsiChar; Data: Pointer): Integer; cdecl;
  external 'ucrtbase.dll' name '_stat64i32';
{$IFEND}

procedure TTestCallbackABI.CRTStatRecordFields;
{$IFDEF C_COMPILER_MSC_64}
var Data: C__stat64i32;
{$ELSE}
{$IFDEF CPUX86}
var Data: C_stat;
{$ENDIF}
{$ENDIF}
begin
  Assert.AreEqual(SizeOf(Winapi.WinSock2.THostEnt), SizeOf(C_hostent));
{$IF DEFINED(C_COMPILER_MSC_32) OR DEFINED(C_COMPILER_MSC_64)}
  Assert.AreEqual(48, SizeOf(Data));
  Assert.AreEqual(NativeUInt(6), NativeUInt(@Data.st_mode) - NativeUInt(@Data));
  Assert.AreEqual(NativeUInt(10), NativeUInt(@Data.st_uid) - NativeUInt(@Data));
  FillChar(Data, SizeOf(Data), $A5);
  Assert.AreEqual(0, ReadUCRTStat('.', @Data));
  Assert.AreEqual(Word($4000), Word(Data.st_mode and $F000), 'UCRT directory mode');
  Assert.AreEqual(SmallInt(0), Data.st_uid);
  Assert.AreEqual(SmallInt(0), Data.st_gid);
{$ELSEIF DEFINED(CPUX86)}
  Assert.AreEqual(36, SizeOf(Data));
  Assert.AreEqual(NativeUInt(4), NativeUInt(@Data.st_mode) - NativeUInt(@Data));
{$IFEND}
end;

type
  TExDupState = record Calls: Integer; Correct: Boolean; Replacement: Pointer; end;
  PExDupState = ^TExDupState;

function DuplicateExData(ToData: CRYPTO_EX_DATA_ptr; const FromData: CRYPTO_EX_DATA_ptr; FromValue: PPointer;
  Index, ArgLong: Integer; Arg: Pointer): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  Inc(PExDupState(Arg)^.Calls);
  PExDupState(Arg)^.Correct := (ToData <> FromData) and (Index >= 0) and
    (ArgLong = -321) and (FromValue <> nil) and (FromValue^ = Pointer(12345));
  FromValue^ := PExDupState(Arg)^.Replacement;
  Result := 1;
end;

procedure TTestCallbackABI.MutableExDataDuplication;
var Source, Dest: CRYPTO_EX_DATA; State: TExDupState; Index: Integer;
begin
  FillChar(Source, SizeOf(Source), 0);
  FillChar(Dest, SizeOf(Dest), 0);
  FillChar(State, SizeOf(State), 0);
  State.Replacement := Pointer(54321);
  Index := CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_APP, -321, @State, nil, DuplicateExData, nil);
  Assert.IsTrue(Index >= 0);
  try
    Assert.AreEqual(1, CRYPTO_new_ex_data(CRYPTO_EX_INDEX_APP, nil, @Source));
    Assert.AreEqual(1, CRYPTO_new_ex_data(CRYPTO_EX_INDEX_APP, nil, @Dest));
    try
      Assert.AreEqual(1, CRYPTO_set_ex_data(@Source, Index, Pointer(12345)));
      Assert.AreEqual(1, CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_APP, @Dest, @Source));
      Assert.AreEqual(1, State.Calls);
      Assert.IsTrue(State.Correct);
      Assert.IsTrue(CRYPTO_get_ex_data(@Source, Index) = Pointer(12345));
      Assert.IsTrue(CRYPTO_get_ex_data(@Dest, Index) = State.Replacement);
    finally
      CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, nil, @Dest);
      CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, nil, @Source);
    end;
  finally
    CRYPTO_free_ex_index(CRYPTO_EX_INDEX_APP, Index);
  end;
end;

function MethodCreate(Bio: BIO_ptr): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin BIO_set_init(Bio, 1); Result := 1; end;
function MethodDestroy(Bio: BIO_ptr): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin Result := 1; end;
function MethodWrite(Bio: BIO_ptr; Buffer: PAnsiChar; Count: Integer): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin Result := Count; end;
function MethodRead(Bio: BIO_ptr; Buffer: PAnsiChar; Count: Integer): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  if Count > 0 then begin Buffer^ := 'R'; Result := 1; end else Result := 0;
end;
function MethodWriteEx(Bio: BIO_ptr; Buffer: PAnsiChar; Count: NativeUInt;
  Written: PNativeUInt): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin Written^ := Count; Result := 1; end;
function MethodReadEx(Bio: BIO_ptr; Buffer: PAnsiChar; Count: NativeUInt;
  ReadBytes: PNativeUInt): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  ReadBytes^ := 0;
  if Count = 0 then Exit(0);
  Buffer^ := 'E'; ReadBytes^ := 1; Result := 1;
end;
function MethodPuts(Bio: BIO_ptr; Text: PAnsiChar): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin Result := Length(AnsiString(Text)); end;
function MethodGets(Bio: BIO_ptr; Buffer: PAnsiChar; Count: Integer): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  if Count < 2 then Exit(0);
  Buffer[0] := 'G'; Buffer[1] := #0; Result := 1;
end;
function MethodCtrl(Bio: BIO_ptr; Cmd, Num: Integer; Arg: Pointer): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  if Cmd = BIO_CTRL_FLUSH then Result := 1
  else if (Cmd = 999) and (Num = -123) and (Arg = Pointer(456)) then Result := -789
  else Result := 0;
end;
function InfoCallback(Bio: BIO_ptr; State, Res: Integer): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin Result := State - Res; end;
function MethodCallbackCtrl(Bio: BIO_ptr; Cmd: Integer; Callback: BIO_info_cb): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin Result := Callback(Bio, Cmd, 9); end;

procedure TTestCallbackABI.BIOMethodCallbackRoundTrip;
var
  Method: BIO_METHOD_ptr; Bio: BIO_ptr; CharBuffer: AnsiChar; ReadCallback: BIO_read_cb;
  WriteExCallback: BIO_write_ex_cb; ReadExCallback: BIO_read_ex_cb;
  TextBuffer: array[0..3] of AnsiChar; Count: NativeUInt;
begin
  Method := BIO_meth_new(BIO_get_new_index or BIO_TYPE_SOURCE_SINK, 'callback ABI');
  Assert.IsNotNull(Method);
  try
    Assert.AreEqual(1, BIO_meth_set_create(Method, MethodCreate));
    Assert.AreEqual(1, BIO_meth_set_destroy(Method, MethodDestroy));
    Assert.AreEqual(1, BIO_meth_set_write(Method, MethodWrite));
    Assert.AreEqual(1, BIO_meth_set_read(Method, MethodRead));
    Assert.AreEqual(1, BIO_meth_set_ctrl(Method, MethodCtrl));
    Assert.AreEqual(1, BIO_meth_set_callback_ctrl(Method, MethodCallbackCtrl));
    Assert.AreEqual(1, BIO_meth_set_puts(Method, MethodPuts));
    Assert.AreEqual(1, BIO_meth_set_gets(Method, MethodGets));
    Assert.IsTrue(@BIO_meth_get_create(Method) = @MethodCreate);
    Assert.IsTrue(@BIO_meth_get_destroy(Method) = @MethodDestroy);
    Assert.IsTrue(@BIO_meth_get_write(Method) = @MethodWrite);
    Assert.IsTrue(@BIO_meth_get_ctrl(Method) = @MethodCtrl);
    Assert.IsTrue(@BIO_meth_get_callback_ctrl(Method) = @MethodCallbackCtrl);
    Assert.IsTrue(@BIO_meth_get_puts(Method) = @MethodPuts);
    Assert.IsTrue(@BIO_meth_get_gets(Method) = @MethodGets);
    ReadCallback := BIO_meth_get_read(Method);
    Assert.IsTrue(@ReadCallback = @MethodRead);
    Bio := BIO_new(Method);
    Assert.IsNotNull(Bio);
    try
      Assert.AreEqual(4, BIO_write(Bio, PAnsiChar(AnsiString('data')), 4));
      Assert.AreEqual(1, BIO_read(Bio, @CharBuffer, 1));
      Assert.AreEqual(AnsiChar('R'), CharBuffer);
      Assert.AreEqual(-789, BIO_ctrl(Bio, 999, -123, Pointer(456)));
      Assert.AreEqual(5, BIO_callback_ctrl(Bio, 14, InfoCallback));
      Assert.AreEqual(1, ReadCallback(Bio, @CharBuffer, 1));
      Assert.AreEqual(3, BIO_puts(Bio, 'abc'));
      Assert.AreEqual(1, BIO_gets(Bio, @TextBuffer[0], SizeOf(TextBuffer)));
      Assert.AreEqual(AnsiChar('G'), TextBuffer[0]);
      Assert.AreEqual(1, BIO_meth_set_write_ex(Method, MethodWriteEx));
      Assert.AreEqual(1, BIO_meth_set_read_ex(Method, MethodReadEx));
      WriteExCallback := BIO_meth_get_write_ex(Method);
      ReadExCallback := BIO_meth_get_read_ex(Method);
      Assert.IsTrue(@WriteExCallback = @MethodWriteEx);
      Assert.IsTrue(@ReadExCallback = @MethodReadEx);
      Assert.AreEqual(1, WriteExCallback(Bio, nil, High(NativeUInt) - 7, @Count));
      Assert.AreEqual(High(NativeUInt) - 7, Count, 'size_t through a returned C callback');
      Assert.AreEqual(1, BIO_write_ex(Bio, @CharBuffer, 1, @Count));
      Assert.AreEqual(NativeUInt(1), Count);
      Assert.AreEqual(1, ReadExCallback(Bio, @CharBuffer, 1, @Count));
      Assert.AreEqual(AnsiChar('E'), CharBuffer);
    finally
      BIO_free(Bio);
    end;
  finally
    BIO_meth_free(Method);
  end;
end;

var ObserverCalls: Integer; ObserverValid: Boolean;
function LegacyObserver(Bio: BIO_ptr; Operation: Integer; const Arg: PAnsiChar;
  ArgInt, ArgLong, Ret: Integer): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  if Operation = ($03 or $80) then
  begin
    Inc(ObserverCalls);
    ObserverValid := (ArgInt = 4) and (ArgLong = 0) and (Ret = 4);
  end;
  Result := Ret;
end;
function Observer(Bio: BIO_ptr; Operation: Integer; const Arg: PAnsiChar; Len: NativeUInt;
  ArgInt, ArgLong, Ret: Integer; Processed: PNativeUInt): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  if Operation = ($03 or $80) then
  begin
    Inc(ObserverCalls);
    ObserverValid := (Len = 4) and (Processed <> nil) and (Processed^ = 4);
  end;
  Result := Ret;
end;

procedure TTestCallbackABI.BIOExtendedObserver;
var Bio: BIO_ptr; Callback: BIO_callback_fn_ex; OldCallback: BIO_callback_fn; Count: NativeUInt;
begin
  Bio := BIO_new(BIO_s_mem);
  Assert.IsNotNull(Bio);
  try
    ObserverCalls := 0; ObserverValid := False;
    BIO_set_callback_ex(Bio, Observer);
    Callback := BIO_get_callback_ex(Bio);
    Assert.IsTrue(@Callback = @Observer);
    Assert.AreEqual(1, BIO_write_ex(Bio, PAnsiChar(AnsiString('test')), 4, @Count));
    Assert.AreEqual(NativeUInt(4), Count);
    Assert.AreEqual(1, ObserverCalls);
    Assert.IsTrue(ObserverValid);
    BIO_set_callback_ex(Bio, nil);
    ObserverCalls := 0; ObserverValid := False;
    BIO_set_callback(Bio, LegacyObserver);
    OldCallback := BIO_get_callback(Bio);
    Assert.IsTrue(@OldCallback = @LegacyObserver);
    Assert.AreEqual(4, BIO_write(Bio, PAnsiChar(AnsiString('more')), 4));
    Assert.AreEqual(1, ObserverCalls);
    Assert.IsTrue(ObserverValid);
    BIO_set_callback(Bio, nil);
  finally
    BIO_free(Bio);
  end;
end;

function AsyncCallback(Arg: Pointer): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin Result := PInteger(Arg)^ + 7; end;

procedure TTestCallbackABI.AsyncCallbackOutputs;
var Ctx: ASYNC_WAIT_CTX_ptr; Callback: ASYNC_callback_fn; Arg: Pointer; Value: Integer;
begin
  Ctx := ASYNC_WAIT_CTX_new;
  Assert.IsNotNull(Ctx);
  try
    Value := 35;
    Assert.AreEqual(1, ASYNC_WAIT_CTX_set_callback(Ctx, AsyncCallback, @Value));
    Callback := nil; Arg := nil;
    Assert.AreEqual(1, ASYNC_WAIT_CTX_get_callback(Ctx, @@Callback, @Arg));
    Assert.IsTrue(@Callback = @AsyncCallback);
    Assert.IsTrue(Arg = @Value);
    Assert.AreEqual(42, Callback(Arg));
  finally
    ASYNC_WAIT_CTX_free(Ctx);
  end;
end;

procedure TTestCallbackABI.PublicRecordFields;
var Buffer: BUF_MEM_ptr; Value: ASN1_TYPE_ptr; Algorithm: X509_ALGOR_ptr; Item: ASN1_ITEM_ptr;
begin
  Buffer := BUF_MEM_new;
  Assert.IsNotNull(Buffer);
  try
    Assert.AreEqual(NativeUInt(17), BUF_MEM_grow_clean(Buffer, 17));
    Assert.AreEqual(NativeUInt(17), Buffer^.length);
    Assert.IsTrue(Buffer^.max >= Buffer^.length);
    Assert.IsNotNull(Buffer^.data);
    Assert.IsTrue(Buffer^.data[16] = #0);
    Assert.AreEqual(Cardinal(0), Buffer^.flags);
  finally BUF_MEM_free(Buffer); end;
  Value := ASN1_TYPE_new;
  Assert.IsNotNull(Value);
  try
    ASN1_TYPE_set(Value, 1, Pointer(1));
    Assert.AreEqual(1, Value^.type_);
    Assert.IsTrue(Value^.value.boolean <> 0);
    ASN1_TYPE_set(Value, 5, nil);
    Assert.AreEqual(5, Value^.type_);
    Assert.IsNull(Value^.value.ptr);
  finally ASN1_TYPE_free(Value); end;
  Algorithm := X509_ALGOR_new;
  Assert.IsNotNull(Algorithm);
  try
    X509_ALGOR_set_md(Algorithm, EVP_sha256);
    Assert.IsNotNull(Algorithm^.algorithm);
    Assert.AreEqual(OBJ_txt2nid('SHA256'), OBJ_obj2nid(Algorithm^.algorithm));
  finally X509_ALGOR_free(Algorithm); end;
  Item := ASN1_ITEM_lookup('X509');
  Assert.IsNotNull(Item);
  Assert.AreEqual('X509', string(AnsiString(Item^.sname)));
  Assert.IsTrue(Item^.size > 0);
  Assert.IsTrue(Item^.tcount > 0);
  Assert.IsNotNull(Item^.templates);
end;

procedure TTestCallbackABI.RandMethodCallbacks;
var Method: RAND_METHOD_ptr; Bytes: array[0..15] of Byte;
begin
  Method := RAND_get_rand_method;
  Assert.IsNotNull(Method);
  Assert.IsTrue(Assigned(Method^.status));
  Assert.IsTrue(Assigned(Method^.bytes));
  Assert.AreEqual(1, Method^.status());
  Assert.AreEqual(1, Method^.bytes(@Bytes[0], SizeOf(Bytes)));
end;

type
  TProviderState = record InitCalls, QueryCalls, FreeCalls: Integer; Valid: Boolean; end;
  PProviderState = ^TProviderState;
var
  ProviderState: TProviderState;
  ProviderDispatch: array[0..2] of OSSL_DISPATCH;
  ProviderAlgorithms: array[0..1] of OSSL_ALGORITHM;

procedure ProviderFree(Context: Pointer); {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  Inc(PProviderState(Context)^.FreeCalls);
end;

function ProviderQuery(Context: Pointer; Operation: Integer; NoCache: PInteger): OSSL_ALGORITHM_ptr;
{$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  Inc(PProviderState(Context)^.QueryCalls);
  NoCache^ := 1;
  if Operation = 12345 then Result := @ProviderAlgorithms[0] else Result := nil;
end;

function ProviderInit(Handle: OSSL_CORE_HANDLE_ptr; Input: OSSL_DISPATCH_ptr;
  Output: OSSL_DISPATCH_ptr_ptr; Context: PPointer): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
var I: Integer; Item: OSSL_DISPATCH_ptr;
begin
  Inc(ProviderState.InitCalls);
  ProviderState.Valid := (Handle <> nil) and (Input <> nil) and (Output <> nil) and (Context <> nil);
  Item := Input;
  I := 0;
  while (I < 256) and (Item^.function_id <> 0) do
  begin
    ProviderState.Valid := ProviderState.Valid and (Item^.function_ <> nil);
    Inc(Item); Inc(I);
  end;
  ProviderState.Valid := ProviderState.Valid and (I > 0) and (I < 256);
  Output^ := @ProviderDispatch[0];
  Context^ := @ProviderState;
  Result := 1;
end;

procedure TTestCallbackABI.ProviderDispatchRecords;
var Context: OSSL_LIB_CTX_ptr; Provider: OSSL_PROVIDER_ptr; Algorithms: OSSL_ALGORITHM_ptr; NoCache: Integer;
begin
  FillChar(ProviderState, SizeOf(ProviderState), 0);
  FillChar(ProviderDispatch, SizeOf(ProviderDispatch), 0);
  FillChar(ProviderAlgorithms, SizeOf(ProviderAlgorithms), 0);
  ProviderDispatch[0].function_id := 1024;
  ProviderDispatch[0].function_ := @ProviderFree;
  ProviderDispatch[1].function_id := 1027;
  ProviderDispatch[1].function_ := @ProviderQuery;
  ProviderAlgorithms[0].algorithm_names := 'ABI-TEST';
  ProviderAlgorithms[0].property_definition := 'provider=abi-test';
  ProviderAlgorithms[0].implementation_ := @ProviderDispatch[2];
  ProviderAlgorithms[0].algorithm_description := 'Record ABI regression';
  Context := OSSL_LIB_CTX_new;
  Assert.IsNotNull(Context);
  try
    Assert.AreEqual(1, OSSL_PROVIDER_add_builtin(Context, 'abi-test', ProviderInit));
    Provider := OSSL_PROVIDER_load(Context, 'abi-test');
    Assert.IsNotNull(Provider);
    try
      Assert.AreEqual(1, ProviderState.InitCalls);
      Assert.IsTrue(ProviderState.Valid);
      NoCache := 0;
      Algorithms := OSSL_PROVIDER_query_operation(Provider, 12345, @NoCache);
      Assert.IsTrue(Algorithms = @ProviderAlgorithms[0]);
      Assert.AreEqual(1, NoCache);
      Assert.AreEqual(1, ProviderState.QueryCalls);
      Assert.AreEqual('ABI-TEST', string(AnsiString(Algorithms^.algorithm_names)));
      OSSL_PROVIDER_unquery_operation(Provider, 12345, Algorithms);
    finally
      OSSL_PROVIDER_unload(Provider);
    end;
  finally
    OSSL_LIB_CTX_free(Context);
  end;
  Assert.AreEqual(1, ProviderState.FreeCalls);
end;

var PasswordCalls, PasswordFlag: Integer;
function PasswordCallback(Buffer: PAnsiChar; Size, RWFlag: Integer; Arg: Pointer): Integer;
{$IFDEF ABI_CDECL}cdecl;{$ENDIF}
var Password: AnsiString;
begin
  Inc(PasswordCalls); PasswordFlag := RWFlag;
  Password := AnsiString(PAnsiChar(Arg));
  if (Size <= Length(Password)) or (Buffer = nil) then Exit(0);
  Move(Password[1], Buffer^, Length(Password));
  Buffer[Length(Password)] := #0;
  Result := Length(Password);
end;

procedure TTestCallbackABI.EncryptedPEMPasswordCallback;
var KeyContext: EVP_PKEY_CTX_ptr; Key, Decoded: EVP_PKEY_ptr; Bio: BIO_ptr; Password: AnsiString;
begin
  Password := 'callback-password';
  KeyContext := EVP_PKEY_CTX_new_from_name(nil, 'ED25519', nil);
  Assert.IsNotNull(KeyContext);
  try
    Assert.AreEqual(1, EVP_PKEY_keygen_init(KeyContext));
    Key := nil;
    Assert.AreEqual(1, EVP_PKEY_generate(KeyContext, @Key));
    try
      Bio := BIO_new(BIO_s_mem);
      Assert.IsNotNull(Bio);
      try
        PasswordCalls := 0; PasswordFlag := -1;
        Assert.AreEqual(1, PEM_write_bio_PrivateKey(Bio, Key, EVP_aes_256_cbc, nil, 0,
          PasswordCallback, PAnsiChar(Password)));
        Assert.IsTrue(PasswordCalls > 0);
        Assert.AreEqual(1, PasswordFlag);
        PasswordCalls := 0; PasswordFlag := -1;
        Decoded := PEM_read_bio_PrivateKey(Bio, nil, PasswordCallback, PAnsiChar(Password));
        Assert.IsNotNull(Decoded);
        try
          Assert.IsTrue(PasswordCalls > 0);
          Assert.AreEqual(0, PasswordFlag);
          Assert.AreEqual(1, EVP_PKEY_eq(Key, Decoded));
        finally
          EVP_PKEY_free(Decoded);
        end;
      finally
        BIO_free(Bio);
      end;
    finally
      EVP_PKEY_free(Key);
    end;
  finally
    EVP_PKEY_CTX_free(KeyContext);
  end;
end;

type
  TEnumeration = record Calls, Aliases, Algorithms: Integer; Valid: Boolean; end;
var Enumeration: TEnumeration;

procedure LegacyAlgorithm(Algorithm: Pointer; const FromName, ToName: PAnsiChar; Arg: Pointer);
{$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  Enumeration.Valid := Enumeration.Valid and (Arg = @Enumeration) and
    (FromName <> nil) and (FromName^ <> #0);
  Inc(Enumeration.Calls);
  if ToName <> nil then
  begin
    Inc(Enumeration.Aliases);
    Enumeration.Valid := Enumeration.Valid and (ToName^ <> #0) and (Algorithm = nil);
  end
  else
  begin
    Inc(Enumeration.Algorithms);
    Enumeration.Valid := Enumeration.Valid and (Algorithm <> nil);
  end;
end;

procedure TTestCallbackABI.LegacyAlgorithmCallbacks;
var I: Integer;
begin
  for I := 0 to 3 do
  begin
    FillChar(Enumeration, SizeOf(Enumeration), 0);
    Enumeration.Valid := True;
    case I of
      0: EVP_MD_do_all(LegacyAlgorithm, @Enumeration);
      1: EVP_MD_do_all_sorted(LegacyAlgorithm, @Enumeration);
      2: EVP_CIPHER_do_all(LegacyAlgorithm, @Enumeration);
      3: EVP_CIPHER_do_all_sorted(LegacyAlgorithm, @Enumeration);
    end;
    Assert.IsTrue(Enumeration.Valid, 'All four callback arguments must arrive intact');
    Assert.IsTrue(Enumeration.Calls > 0);
    Assert.IsTrue(Enumeration.Algorithms > 0);
    Assert.IsTrue(Enumeration.Aliases > 0);
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TTestCallbackABI);

end.
