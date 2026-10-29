unit TestOpenSSLAdditionalABI;

interface

uses
  System.SysUtils, Winapi.Windows, Winapi.WinSock2,
  DUnitX.TestFramework, libOpenSSL3;

{$IF DEFINED(C_COMPILER_BCC32C) OR DEFINED(C_COMPILER_MSC_32)}
{$DEFINE ABI_CDECL}
{$IFEND}

type
  [TestFixture]
  TTestAdditionalABI = class
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure ParameterBuilderScalars;
    [Test] procedure OctetStringOutputLengths;
    [Test] procedure MemoryAndStringUtilities;
    [Test] procedure StackCallbacksAndSort;
    [Test] procedure LHashCallbacksAndFlush;
    [Test] procedure ExtendedDataRecordAndCallbacks;
    [Test] procedure NumericAddressLookup;
    [Test] procedure CustomBIOWriteCallback;
    [Test] procedure CipherBIOResult;
    [Test] procedure Base64EncodeDecode;
    [Test] procedure AlgorithmNameCallbacks;
    [Test] procedure RandomSeedVoidAPIs;
    [Test] procedure BigNumberNativeWords;
    [Test] procedure ThreadIdentifiers;
    [Test] procedure ExtendedTimeTRoundTrip;
    [Test] procedure X509AlgorithmReturnType;
    [Test] procedure ECGroupSeedBytes;
    [Test] procedure ObjectNameEnumerations;
    [Test] procedure BIOVaListFormatting;
    [Test] procedure HPKESuiteValueRecord;
    [Test] procedure TLSNarrowScalars;
  end;

implementation

procedure Success(Value: Integer; const Operation: string);
begin
  Assert.AreEqual(1, Value, Operation);
end;

procedure TTestAdditionalABI.Setup;
begin
  Success(OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nil), 'Initialize ABI fixture');
  ERR_clear_error;
end;

procedure TTestAdditionalABI.TearDown;
begin
  ERR_clear_error;
end;

function SampleTime: C__TIME_T;
begin
{$IF DEFINED(CPUX64) OR DEFINED(C_COMPILER_MSC_32)}
  Result := 2208988800; // 2040-01-01: exercises the high return register on MSVC Win32.
{$ELSE}
  Result := 946684800;  // 2000-01-01 fits the Borland Win32 time_t ABI.
{$IFEND}
end;

procedure TTestAdditionalABI.ParameterBuilderScalars;
var
  Builder: OSSL_PARAM_BLD_ptr;
  Params, Param: OSSL_PARAM_ptr;
  SignedValue: Integer;
  UnsignedValue: Cardinal;
  Epoch: C__TIME_T;
begin
  Builder := OSSL_PARAM_BLD_new;
  Assert.IsNotNull(Builder);
  try
    Success(OSSL_PARAM_BLD_push_long(Builder, 'long', -1234567), 'Push signed long');
    Success(OSSL_PARAM_BLD_push_ulong(Builder, 'ulong', $FEDCBA98), 'Push unsigned long');
    Success(OSSL_PARAM_BLD_push_int32(Builder, 'int32', Low(Integer)), 'Push int32');
    Success(OSSL_PARAM_BLD_push_time_t(Builder, 'time', SampleTime), 'Push time_t');
    Params := OSSL_PARAM_BLD_to_param(Builder);
    Assert.IsNotNull(Params);
    try
      Param := OSSL_PARAM_locate(Params, 'long');
      Assert.IsNotNull(Param);
      Success(OSSL_PARAM_get_long(Param, @SignedValue), 'Get long');
      Assert.AreEqual(-1234567, SignedValue);
      Param := OSSL_PARAM_locate(Params, 'ulong');
      Success(OSSL_PARAM_get_ulong(Param, @UnsignedValue), 'Get ulong');
      Assert.AreEqual(Cardinal($FEDCBA98), UnsignedValue);
      Param := OSSL_PARAM_locate(Params, 'int32');
      Success(OSSL_PARAM_get_int32(Param, @SignedValue), 'Get int32');
      Assert.AreEqual(Low(Integer), SignedValue);
      Param := OSSL_PARAM_locate(Params, 'time');
      Success(OSSL_PARAM_get_time_t(Param, @Epoch), 'Get time_t');
      Assert.AreEqual(Int64(SampleTime), Int64(Epoch));
    finally
      OSSL_PARAM_free(Params);
    end;
  finally
    OSSL_PARAM_BLD_free(Builder);
  end;
end;

procedure TTestAdditionalABI.OctetStringOutputLengths;
const Source: array[0..5] of Byte = (0, 1, $FF, 0, $80, 6);
var
  Param: OSSL_PARAM;
  CopyBuffer: Pointer;
  Used: NativeUInt;
  Small: array[0..7] of Byte;
  I: Integer;
begin
  Param := OSSL_PARAM_construct_octet_string('bytes', @Source[0], SizeOf(Source));
  CopyBuffer := nil;
  Success(OSSL_PARAM_get_octet_string(@Param, @CopyBuffer, 0, @Used), 'Allocate octet copy');
  try
    Assert.AreEqual(NativeUInt(SizeOf(Source)), Used);
    Assert.IsNotNull(CopyBuffer);
    Assert.IsTrue(CompareMem(CopyBuffer, @Source[0], Used));
  finally
    OPENSSL_free(CopyBuffer);
  end;
  FillChar(Small, SizeOf(Small), $CC);
  CopyBuffer := @Small[0];
  Used := 0;
  Assert.AreEqual(0, OSSL_PARAM_get_octet_string(@Param, @CopyBuffer, 3, @Used));
  Assert.AreEqual(NativeUInt(SizeOf(Source)), Used);
  for I := 0 to High(Small) do Assert.AreEqual(Byte($CC), Small[I], 'No partial copy on overflow');
end;

procedure TTestAdditionalABI.MemoryAndStringUtilities;
var
  Buffer: array[0..7] of AnsiChar;
  Left, Right: array[0..3] of Byte;
  CopyBuffer: PAnsiChar;
begin
  FillChar(Buffer, SizeOf(Buffer), $7F);
  Assert.AreEqual(NativeUInt(7), OPENSSL_strlcpy(@Buffer[0], 'abcdefg', 4));
  Assert.AreEqual('abc', string(AnsiString(PAnsiChar(@Buffer[0]))));
  Assert.AreEqual(AnsiChar(#$7F), Buffer[4]);
  Assert.AreEqual(NativeUInt(7), OPENSSL_strlcat(@Buffer[0], 'defg', 6));
  Assert.AreEqual('abcde', string(AnsiString(PAnsiChar(@Buffer[0]))));
  Assert.AreEqual(AnsiChar(#$7F), Buffer[6]);
  Assert.AreEqual(NativeUInt(3), OPENSSL_strnlen('abcdef', 3));
  Assert.AreEqual(0, OPENSSL_strcasecmp('AbC', 'aBc'));
  CopyBuffer := CRYPTO_strndup('abcdef', 3, nil, 0);
  Assert.IsNotNull(CopyBuffer);
  try
    Assert.AreEqual('abc', string(AnsiString(CopyBuffer)));
  finally
    OPENSSL_free(CopyBuffer);
  end;
  FillChar(Left, SizeOf(Left), $A5);
  Right := Left;
  Assert.AreEqual(0, CRYPTO_memcmp(@Left[0], @Right[0], SizeOf(Left)));
  Right[3] := Right[3] xor 1;
  Assert.IsTrue(CRYPTO_memcmp(@Left[0], @Right[0], SizeOf(Left)) <> 0);
  Assert.AreEqual(0, CRYPTO_memcmp(nil, nil, 0));
end;

function CompareStack(const Left, Right: Pointer): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
var A, B: NativeUInt;
begin
  A := NativeUInt(PPointer(Left)^);
  B := NativeUInt(PPointer(Right)^);
  if A < B then Result := -1
  else if A > B then Result := 1
  else Result := 0;
end;

procedure TTestAdditionalABI.StackCallbacksAndSort;
var Stack: OPENSSL_STACK_ptr;
begin
  Stack := OPENSSL_sk_new(CompareStack);
  Assert.IsNotNull(Stack);
  try
    Assert.AreEqual(1, OPENSSL_sk_push(Stack, Pointer(3)));
    Assert.AreEqual(2, OPENSSL_sk_push(Stack, Pointer(1)));
    Assert.AreEqual(3, OPENSSL_sk_push(Stack, Pointer(2)));
    OPENSSL_sk_sort(Stack);
    Assert.AreEqual(1, OPENSSL_sk_is_sorted(Stack));
    Assert.IsTrue(OPENSSL_sk_value(Stack, 0) = Pointer(1));
    Assert.AreEqual(1, OPENSSL_sk_find(Stack, Pointer(2)));
    Assert.IsTrue(OPENSSL_sk_pop(Stack) = Pointer(3));
    Assert.AreEqual(2, OPENSSL_sk_num(Stack));
  finally
    OPENSSL_sk_free(Stack);
  end;
end;

function HashPointer(const Item: Pointer): Cardinal; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin Result := Cardinal(NativeUInt(Item)); end;

function ComparePointer(const Left, Right: Pointer): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  if NativeUInt(Left) < NativeUInt(Right) then Result := -1
  else if Left <> Right then Result := 1
  else Result := 0;
end;

procedure TTestAdditionalABI.LHashCallbacksAndFlush;
var Hash: OPENSSL_LHASH_ptr;
begin
  Hash := OPENSSL_LH_new(HashPointer, ComparePointer);
  Assert.IsNotNull(Hash);
  try
    Assert.IsNull(OPENSSL_LH_insert(Hash, Pointer(42)));
    Assert.IsNull(OPENSSL_LH_insert(Hash, Pointer(17)));
    Assert.IsTrue(OPENSSL_LH_retrieve(Hash, Pointer(42)) = Pointer(42));
    Assert.AreEqual(Cardinal(2), OPENSSL_LH_num_items(Hash));
    OPENSSL_LH_flush(Hash);
    Assert.AreEqual(Cardinal(0), OPENSSL_LH_num_items(Hash));
    Assert.IsNull(OPENSSL_LH_retrieve(Hash, Pointer(42)));
  finally
    OPENSSL_LH_free(Hash);
  end;
end;

type
  TExState = record
    NewCalls, FreeCalls: Integer;
    ArgumentsCorrect: Boolean;
  end;
  PExState = ^TExState;

procedure ExNew(Parent, Item: Pointer; Data: CRYPTO_EX_DATA_ptr;
  Index, ArgLong: Integer; Arg: Pointer); {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  Inc(PExState(Arg)^.NewCalls);
  PExState(Arg)^.ArgumentsCorrect := (ArgLong = -17) and (Parent = Pointer(123)) and (Data <> nil);
end;

procedure ExFree(Parent, Item: Pointer; Data: CRYPTO_EX_DATA_ptr;
  Index, ArgLong: Integer; Arg: Pointer); {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  Inc(PExState(Arg)^.FreeCalls);
end;

procedure TTestAdditionalABI.ExtendedDataRecordAndCallbacks;
var
  Storage: record Data: CRYPTO_EX_DATA; Canary: NativeUInt; end;
  State: TExState;
  Index: Integer;
begin
  Assert.AreEqual(NativeInt(2 * SizeOf(Pointer)), NativeInt(SizeOf(CRYPTO_EX_DATA)));
  Assert.AreEqual(NativeUInt(SizeOf(Pointer)), NativeUInt(@Storage.Data.sk) - NativeUInt(@Storage.Data));
  FillChar(Storage, SizeOf(Storage), 0);
  FillChar(State, SizeOf(State), 0);
  Storage.Canary := $12345678;
  Index := CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_APP, -17, @State, ExNew, nil, ExFree);
  Assert.IsTrue(Index >= 0);
  try
    Success(CRYPTO_new_ex_data(CRYPTO_EX_INDEX_APP, Pointer(123), @Storage.Data), 'Allocate extended data');
    try
      Success(CRYPTO_set_ex_data(@Storage.Data, Index, Pointer(456)), 'Set extended data');
      Assert.IsTrue(CRYPTO_get_ex_data(@Storage.Data, Index) = Pointer(456));
      Assert.AreEqual(1, State.NewCalls);
      Assert.IsTrue(State.ArgumentsCorrect);
      Assert.AreEqual(NativeUInt($12345678), Storage.Canary);
    finally
      CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, Pointer(123), @Storage.Data);
    end;
    Assert.AreEqual(1, State.FreeCalls);
    Assert.AreEqual(NativeUInt($12345678), Storage.Canary);
  finally
    Success(CRYPTO_free_ex_index(CRYPTO_EX_INDEX_APP, Index), 'Release extended data index');
  end;
end;

procedure TTestAdditionalABI.NumericAddressLookup;
var Info: BIO_ADDRINFO_ptr;
begin
  Success(BIO_sock_init, 'Initialize socket ABI');
  Info := nil;
  Success(BIO_lookup_ex('127.0.0.1', '443', Ord(BIO_LOOKUP_CLIENT), AF_INET, SOCK_STREAM, IPPROTO_TCP, @Info),
    'Resolve numeric address without DNS');
  Assert.IsNotNull(Info);
  try
    Assert.AreEqual(AF_INET, BIO_ADDRINFO_family(Info));
    Assert.AreEqual(SOCK_STREAM, BIO_ADDRINFO_socktype(Info));
    Assert.AreEqual(443, Integer(ntohs(BIO_ADDR_rawport(BIO_ADDRINFO_address(Info)))));
  finally
    BIO_ADDRINFO_free(Info);
  end;
end;

function CustomWrite(Bio: BIO_ptr; Data: PAnsiChar; Size: NativeUInt;
  Written: PNativeUInt): Integer; {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  Inc(PInteger(BIO_get_data(Bio))^);
  Written^ := Size;
  Result := 1;
end;

procedure TTestAdditionalABI.CustomBIOWriteCallback;
var Method: BIO_METHOD_ptr; Bio: BIO_ptr; Calls: Integer; Written: NativeUInt;
begin
  Method := BIO_meth_new(BIO_get_new_index or BIO_TYPE_SOURCE_SINK, 'ABI writer');
  Assert.IsNotNull(Method);
  try
    Success(BIO_meth_set_write_ex(Method, @CustomWrite), 'Install BIO callback');
    Bio := BIO_new_ex(nil, Method);
    Assert.IsNotNull(Bio);
    try
      Calls := 0;
      BIO_set_data(Bio, @Calls);
      BIO_set_init(Bio, 1);
      Success(BIO_write_ex(Bio, PAnsiChar('test'), 4, @Written), 'Call custom BIO');
      Assert.AreEqual(1, Calls);
      Assert.AreEqual(NativeUInt(4), Written);
      Assert.AreEqual(1, BIO_get_init(Bio));
    finally
      BIO_free(Bio);
    end;
  finally
    BIO_meth_free(Method);
  end;
end;

procedure TTestAdditionalABI.CipherBIOResult;
var Filter, Sink: BIO_ptr; Key, IV: array[0..15] of Byte; Data: array[0..15] of Byte;
begin
  FillChar(Key, SizeOf(Key), 0);
  FillChar(IV, SizeOf(IV), 0);
  FillChar(Data, SizeOf(Data), 0);
  Filter := BIO_new(BIO_f_cipher);
  Assert.IsNotNull(Filter);
  try
    Success(BIO_set_cipher(Filter, EVP_aes_128_cbc, @Key[0], @IV[0], 1), 'Configure cipher BIO');
    Sink := BIO_new(BIO_s_mem);
    Assert.IsNotNull(Sink);
    try
      Assert.IsNotNull(BIO_push(Filter, Sink));
      Assert.AreEqual(16, BIO_write(Filter, @Data[0], SizeOf(Data)));
      Assert.AreEqual(1, BIO_flush(Filter));
      Assert.AreEqual(32, BIO_pending(Sink), 'CBC adds a full padding block');
    finally
      BIO_pop(Filter);
      BIO_free(Sink);
    end;
  finally
    BIO_free(Filter);
  end;
end;

procedure TTestAdditionalABI.Base64EncodeDecode;
var Ctx: EVP_ENCODE_CTX_ptr; Encoded, Decoded: array[0..63] of Byte; Count, Last, DecodedCount: Integer;
begin
  Ctx := EVP_ENCODE_CTX_new;
  Assert.IsNotNull(Ctx);
  try
    EVP_EncodeInit(Ctx);
    Success(EVP_EncodeUpdate(Ctx, @Encoded[0], @Count, PByte(PAnsiChar('foobar')), 6), 'Encode update');
    EVP_EncodeFinal(Ctx, @Encoded[Count], @Last);
    Inc(Count, Last);
    Assert.AreEqual(9, Count);
    Assert.IsTrue(CompareMem(@Encoded[0], PAnsiChar('Zm9vYmFy'#10), 9));
    EVP_DecodeInit(Ctx);
    Assert.IsTrue(EVP_DecodeUpdate(Ctx, @Decoded[0], @DecodedCount, @Encoded[0], Count) >= 0);
    Success(EVP_DecodeFinal(Ctx, @Decoded[DecodedCount], @Last), 'Decode final');
    Assert.AreEqual(6, DecodedCount + Last);
    Assert.IsTrue(CompareMem(@Decoded[0], PAnsiChar('foobar'), 6));
  finally
    EVP_ENCODE_CTX_free(Ctx);
  end;
end;

procedure CountName(const Name: PAnsiChar; Arg: Pointer); {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  if (Name <> nil) and (Name^ <> #0) then Inc(PInteger(Arg)^);
end;

procedure TTestAdditionalABI.AlgorithmNameCallbacks;
var Digest: EVP_MD_ptr; Cipher: EVP_CIPHER_ptr; Count: Integer;
begin
  Digest := EVP_MD_fetch(nil, 'SHA256', nil);
  Assert.IsNotNull(Digest);
  try
    Count := 0;
    Success(EVP_MD_names_do_all(Digest, CountName, @Count), 'Enumerate digest names');
    Assert.IsTrue(Count > 0);
  finally
    EVP_MD_free(Digest);
  end;
  Cipher := EVP_CIPHER_fetch(nil, 'AES-128-CBC', nil);
  Assert.IsNotNull(Cipher);
  try
    Count := 0;
    Success(EVP_CIPHER_names_do_all(Cipher, CountName, @Count), 'Enumerate cipher names');
    Assert.IsTrue(Count > 0);
  finally
    EVP_CIPHER_free(Cipher);
  end;
end;

procedure TTestAdditionalABI.RandomSeedVoidAPIs;
const Seed: array[0..7] of Byte = (1, 2, 3, 4, 5, 6, 7, 8);
var Output: array[0..15] of Byte;
begin
  RAND_seed(@Seed[0], SizeOf(Seed));
  RAND_add(@Seed[0], SizeOf(Seed), 0.0);
  Success(RAND_status, 'Random generator status after void seed APIs');
  Success(RAND_bytes(@Output[0], SizeOf(Output)), 'Random bytes');
end;

procedure TTestAdditionalABI.BigNumberNativeWords;
var Number: BIGNUM_ptr; Value: BN_ULONG;
begin
{$IF DEFINED(CPUX64) AND NOT DEFINED(C_COMPILER_BORLAND_64)}
  Value := $100000001;
{$ELSE}
  Value := $F1234567;
{$IFEND}
  Number := BN_new;
  Assert.IsNotNull(Number);
  try
    Success(BN_set_word(Number, Value), 'BN native word input');
    Assert.AreEqual(Value, BN_get_word(Number), 'No truncation above 32 bits on Win64');
    Assert.AreEqual(Value mod 17, BN_mod_word(Number, 17));
    Success(BN_add_word(Number, 5), 'BN native word addition');
    Assert.AreEqual(Value + 5, BN_get_word(Number));
  finally
    BN_free(Number);
  end;
end;

procedure TTestAdditionalABI.ThreadIdentifiers;
var ID: Cardinal;
begin
  ID := CRYPTO_THREAD_get_current_id;
  Assert.AreEqual(GetCurrentThreadId, ID);
  Assert.AreEqual(1, CRYPTO_THREAD_compare_id(ID, ID));
  Assert.AreEqual(0, CRYPTO_THREAD_compare_id(ID, ID xor 1));
end;

procedure TTestAdditionalABI.ExtendedTimeTRoundTrip;
var Params: X509_VERIFY_PARAM_ptr; Session: SSL_SESSION_ptr; Time: ASN1_TIME_ptr; Epoch: C__TIME_T; BrokenDown: C_tm;
begin
  Epoch := SampleTime;
  Params := X509_VERIFY_PARAM_new;
  Assert.IsNotNull(Params);
  try
    X509_VERIFY_PARAM_set_time(Params, Epoch);
    Assert.AreEqual(Int64(Epoch), Int64(X509_VERIFY_PARAM_get_time(Params)));
  finally
    X509_VERIFY_PARAM_free(Params);
  end;
  Session := SSL_SESSION_new;
  Assert.IsNotNull(Session);
  try
    Assert.AreEqual(Int64(Epoch), Int64(SSL_SESSION_set_time_ex(Session, Epoch)));
    Assert.AreEqual(Int64(Epoch), Int64(SSL_SESSION_get_time_ex(Session)));
  finally
    SSL_SESSION_free(Session);
  end;
  Time := ASN1_TIME_set(nil, Epoch);
  Assert.IsNotNull(Time);
  try
    Success(ASN1_TIME_to_tm(Time, @BrokenDown), 'Decode time_t timestamp');
{$IF DEFINED(CPUX64) OR DEFINED(C_COMPILER_MSC_32)}
    Assert.AreEqual(2040 - 1900, BrokenDown.tm_year);
{$ELSE}
    Assert.AreEqual(2000 - 1900, BrokenDown.tm_year);
{$IFEND}
    Assert.IsNotNull(X509_time_adj_ex(Time, 1, 0, @Epoch));
    Success(ASN1_TIME_to_tm(Time, @BrokenDown), 'Decode adjusted time_t pointer');
    Assert.AreEqual(2, BrokenDown.tm_mday);
  finally
    ASN1_TIME_free(Time);
  end;
end;

procedure TTestAdditionalABI.X509AlgorithmReturnType;
var Algorithm: X509_ALGOR_ptr; Obj: ASN1_OBJECT_ptr; LookupObject: X509_OBJECT_ptr;
begin
  LookupObject := X509_OBJECT_new;
  Assert.IsNotNull(LookupObject);
  try
    Assert.AreEqual(0, X509_OBJECT_get_type(LookupObject), 'Empty lookup object enum');
  finally
    X509_OBJECT_free(LookupObject);
  end;
  Algorithm := X509_ALGOR_new;
  Assert.IsNotNull(Algorithm);
  try
{$IFDEF OPENSSL_3X}
    X509_ALGOR_set_md(Algorithm, EVP_sha256);
{$ELSE}
    Success(X509_ALGOR_set_md(Algorithm, EVP_sha256), '4.x algorithm setter status');
{$ENDIF}
    Obj := nil;
    X509_ALGOR_get0(@Obj, nil, nil, Algorithm);
    Assert.IsNotNull(Obj);
    Assert.AreEqual(OBJ_txt2nid('SHA256'), OBJ_obj2nid(Obj));
  finally
    X509_ALGOR_free(Algorithm);
  end;
end;

procedure TTestAdditionalABI.ECGroupSeedBytes;
const Seed: array[0..4] of Byte = (0, $FF, 1, $80, 2);
var Group: EC_GROUP_ptr;
begin
  Group := EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  Assert.IsNotNull(Group);
  try
    Assert.AreEqual(NativeUInt(SizeOf(Seed)), EC_GROUP_set_seed(Group, @Seed[0], SizeOf(Seed)));
    Assert.AreEqual(NativeUInt(SizeOf(Seed)), EC_GROUP_get_seed_len(Group));
    Assert.IsTrue(CompareMem(EC_GROUP_get0_seed(Group), @Seed[0], SizeOf(Seed)));
  finally
    EC_GROUP_free(Group);
  end;
end;

procedure CountObjectName(Name, Arg: Pointer); {$IFDEF ABI_CDECL}cdecl;{$ENDIF}
begin
  if Name <> nil then Inc(PInteger(Arg)^);
end;

procedure TTestAdditionalABI.ObjectNameEnumerations;
const DigestNameType = 1; // OBJ_NAME_TYPE_MD_METH from openssl/objects.h.
var Before, Count: Integer;
begin
  Before := 0;
  OBJ_NAME_do_all(DigestNameType, @CountObjectName, @Before);
  Success(OBJ_NAME_add('abi-enumeration', DigestNameType, 'payload'), 'Register object name');
  try
    Count := 0;
    OBJ_NAME_do_all(DigestNameType, @CountObjectName, @Count);
    Assert.AreEqual(Before + 1, Count);
    Count := 0;
    OBJ_NAME_do_all_sorted(DigestNameType, @CountObjectName, @Count);
    Assert.AreEqual(Before + 1, Count);
  finally
    Success(OBJ_NAME_remove('abi-enumeration', DigestNameType), 'Remove object name');
  end;
end;

procedure TTestAdditionalABI.BIOVaListFormatting;
var
  Args: array[0..1] of NativeUInt;
  Buffer: array[0..31] of AnsiChar;
  Bio: BIO_ptr;
begin
  // Windows va_list is a pointer to consecutive native-width argument slots.
  Args[0] := 17;
  Args[1] := 23;
  FillChar(Buffer, SizeOf(Buffer), 0);
  Assert.AreEqual(5, BIO_vsnprintf(@Buffer[0], SizeOf(Buffer), '%d:%d', @Args[0]));
  Assert.AreEqual('17:23', string(AnsiString(PAnsiChar(@Buffer[0]))));
  Bio := BIO_new(BIO_s_mem);
  Assert.IsNotNull(Bio);
  try
    Assert.AreEqual(5, BIO_vprintf(Bio, '%d:%d', @Args[0]));
    FillChar(Buffer, SizeOf(Buffer), 0);
    Assert.AreEqual(5, BIO_read(Bio, @Buffer[0], SizeOf(Buffer) - 1));
    Assert.AreEqual('17:23', string(AnsiString(PAnsiChar(@Buffer[0]))));
  finally
    BIO_free(Bio);
  end;
end;

procedure TTestAdditionalABI.HPKESuiteValueRecord;
var
  Suite: OSSL_HPKE_SUITE;
  Ctx: OSSL_HPKE_CTX_ptr;
  PublicKey: array[0..63] of Byte;
  PublicLength: NativeUInt;
  PrivateKey: EVP_PKEY_ptr;
{$IFDEF OPENSSL_4X}
  Store: Pointer;
{$ENDIF}
begin
  Assert.AreEqual(6, SizeOf(Suite));
  Suite.kem_id := $20;
  Suite.kdf_id := 1;
  Suite.aead_id := 1;
  Success(OSSL_HPKE_suite_check(Suite), 'HPKE suite by value');
  Assert.AreEqual(NativeUInt(32), OSSL_HPKE_get_public_encap_size(Suite));
  Assert.AreEqual(NativeUInt(33), OSSL_HPKE_get_ciphertext_size(Suite, 17));
  Assert.IsTrue(OSSL_HPKE_get_recommended_ikmelen(Suite) >= 32);
  Ctx := OSSL_HPKE_CTX_new(0, Suite, 0, nil, nil);
  Assert.IsNotNull(Ctx, 'Arguments following the suite record');
  OSSL_HPKE_CTX_free(Ctx);
  PublicLength := SizeOf(PublicKey);
  PrivateKey := nil;
  Success(OSSL_HPKE_keygen(Suite, @PublicKey[0], @PublicLength, @PrivateKey,
    nil, 0, nil, nil), 'HPKE key generation arguments');
  try
    Assert.IsNotNull(PrivateKey);
    Assert.AreEqual(NativeUInt(32), PublicLength);
  finally
    EVP_PKEY_free(PrivateKey);
  end;
{$IFDEF OPENSSL_4X}
  Store := OSSL_ECHSTORE_new(nil, nil);
  Assert.IsNotNull(Store);
  try
    Success(OSSL_ECHSTORE_new_config(Store, $FE0D, 64, 'public.example', Suite),
      'ECH narrow scalars followed by suite record');
  finally
    OSSL_ECHSTORE_free(Store);
  end;
{$ENDIF}
  Suite.kem_id := $FFFF;
  Assert.AreEqual(0, OSSL_HPKE_suite_check(Suite));
end;

procedure TTestAdditionalABI.TLSNarrowScalars;
const CipherID: array[0..1] of Byte = ($13, $01);
var Ctx: SSL_CTX_ptr; Connection: SSL_ptr; Session: SSL_SESSION_ptr; Cipher: SSL_CIPHER_ptr;
begin
  Ctx := SSL_CTX_new(TLS_method);
  Assert.IsNotNull(Ctx);
  try
    Success(SSL_CTX_set_tlsext_max_fragment_length(Ctx, 1), 'Context fragment size');
    Assert.AreEqual(0, SSL_CTX_set_tlsext_max_fragment_length(Ctx, $FF));
    Connection := SSL_new(Ctx);
    Assert.IsNotNull(Connection);
    try
      Assert.AreEqual(0, SSL_get_state(Connection), 'Initial handshake state enum');
      Success(SSL_set_tlsext_max_fragment_length(Connection, 2), 'Connection fragment size');
      Assert.AreEqual(0, SSL_set_tlsext_max_fragment_length(Connection, $FF));
      Cipher := SSL_CIPHER_find(Connection, @CipherID[0]);
      Assert.IsNotNull(Cipher);
      Assert.AreEqual(Word($1301), SSL_CIPHER_get_protocol_id(Cipher));
      Assert.AreEqual(NativeInt(-1), SSL_sendfile(Connection, -1, -123, 0, 0), 'Signed ssize_t error');
    finally
      SSL_free(Connection);
    end;
    Session := SSL_SESSION_new;
    Assert.IsNotNull(Session);
    try
      Assert.AreEqual(Byte(0), SSL_SESSION_get_max_fragment_length(Session));
    finally
      SSL_SESSION_free(Session);
    end;
  finally
    SSL_CTX_free(Ctx);
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TTestAdditionalABI);

end.
