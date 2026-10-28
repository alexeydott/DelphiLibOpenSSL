unit TestOpenSSLRegressions;

interface

uses
  System.SysUtils, Winapi.WinSock2, DUnitX.TestFramework, libOpenSSL3;

type
  [TestFixture]
  TTestInteropRegressions = class
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure ParamUInt64RoundTrip;
    [Test] procedure ParamSignedLongAndInt32;
    [Test] procedure ParamUnsignedLong;
    [Test] procedure ParamSizeTAndTimeT;
    [Test] procedure ParamBigNumber;
    [Test] procedure AddressIPv4;
    [Test] procedure AddressIPv6;
    [Test] procedure BIOPairBackpressure;
    [Test] procedure ASN1TimeBoundaries;
    [Test] procedure IsolatedProviderReload;
  end;

  [TestFixture]
  TTestCryptoRegressions = class
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure AESGCMKnownVector;
    [Test] procedure AESGCMRejectsModifiedTag;
    [Test] procedure AESCBCRejectsInvalidPadding;
    [Test] procedure PBKDF2KnownVector;
    [Test] procedure RSASignatureRejectsModifiedMessage;
    [Test] procedure ECDHSharedSecret;
    [Test] procedure ProviderHMAC;
  end;

  [TestFixture]
  TTestTLSRegressions = class
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure TLS12HandshakeAndData;
    [Test] procedure TLS13HandshakeAndData;
    [Test] procedure RejectUntrustedCertificate;
    [Test] procedure DuplicateNegotiatedSession;
    [Test] procedure BidirectionalShutdown;
  end;

{$IFNDEF OPENSSL_3X}
  [TestFixture]
  TTestSKeyRegressions = class
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure ManagementReferenceCounting;
    [Test] procedure RawKeyReferenceCounting;
  end;
{$ENDIF}

implementation

const
  MaxHandshakeSteps = 128;
  GCMGetTag = $10;
  GCMSetTag = $11;

procedure Check(Code: Integer; const Operation: string);
begin
  Assert.AreEqual(1, Code, Operation);
end;

procedure Initialize;
begin
  Check(OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, nil), 'OpenSSL initialization');
  ERR_clear_error;
end;

function Hex(const Data: array of Byte; Count: Integer): string;
var I: Integer;
begin
  Result := '';
  for I := 0 to Count - 1 do
    Result := Result + LowerCase(IntToHex(Data[I], 2));
end;

procedure TTestInteropRegressions.Setup;
begin Initialize; end;
procedure TTestInteropRegressions.TearDown;
begin ERR_clear_error; end;
procedure TTestCryptoRegressions.Setup;
begin Initialize; end;
procedure TTestCryptoRegressions.TearDown;
begin ERR_clear_error; end;
procedure TTestTLSRegressions.Setup;
begin Initialize; end;
procedure TTestTLSRegressions.TearDown;
begin ERR_clear_error; end;

procedure TTestInteropRegressions.ParamUInt64RoundTrip;
var
  Value, ReadBack: UInt64;
  Param, Terminator: OSSL_PARAM;
begin
  Value := $123456789ABCDEF0;
  Param := OSSL_PARAM_construct_uint64('value', @Value);
  Assert.AreEqual('value', string(AnsiString(Param.key)));
  Assert.IsTrue(Param.data = @Value);
  Assert.AreEqual(NativeUInt(8), Param.data_size);
  Check(OSSL_PARAM_get_uint64(@Param, @ReadBack), 'Read uint64 parameter');
  Assert.AreEqual(Value, ReadBack);
  Check(OSSL_PARAM_set_uint64(@Param, $FEDCBA9876543210), 'Write uint64 parameter');
  Assert.AreEqual(UInt64($FEDCBA9876543210), Value);
  Terminator := OSSL_PARAM_construct_end;
  Assert.IsNull(Terminator.key);
  Assert.IsNull(Terminator.data);
end;

procedure TTestInteropRegressions.ParamSizeTAndTimeT;
var
  Value, ReadBack: NativeUInt;
  Epoch, ReadEpoch: C__TIME_T;
  Param: OSSL_PARAM;
begin
  Value := High(NativeUInt) - 17;
  Param := OSSL_PARAM_construct_size_t('length', @Value);
  Assert.IsTrue(Param.data = @Value);
  Assert.AreEqual(NativeUInt(SizeOf(Value)), Param.data_size);
  Check(OSSL_PARAM_get_size_t(@Param, @ReadBack), 'Read size_t parameter');
  Assert.AreEqual(Value, ReadBack);
  Epoch := 946684800;
  Param := OSSL_PARAM_construct_time_t('time', @Epoch);
  Assert.IsTrue(Param.data = @Epoch);
  Assert.AreEqual(NativeUInt(SizeOf(Epoch)), Param.data_size, 'Producer time_t width');
  Check(OSSL_PARAM_get_time_t(@Param, @ReadEpoch), 'Read time_t parameter');
  Assert.AreEqual(Int64(Epoch), Int64(ReadEpoch));
  Check(OSSL_PARAM_set_time_t(@Param, Epoch + 60), 'Write time_t parameter');
  Assert.AreEqual(Int64(946684860), Int64(Epoch));
end;

procedure TTestInteropRegressions.ParamSignedLongAndInt32;
var
  Value: Integer;
  Dest: record Value: Integer; Canary: Cardinal; end;
  Param: OSSL_PARAM;
begin
  Value := -1234567;
  Dest.Canary := $DEADBEEF;
  Param := OSSL_PARAM_construct_long('signed-long', @Value);
  Assert.AreEqual(NativeUInt(4), Param.data_size, 'Windows C long is always 32 bits');
  Check(OSSL_PARAM_get_long(@Param, @Dest.Value), 'Read signed long');
  Assert.AreEqual(Value, Dest.Value);
  Assert.AreEqual(Cardinal($DEADBEEF), Dest.Canary);
  Check(OSSL_PARAM_set_long(@Param, -7654321), 'Write signed long');
  Assert.AreEqual(-7654321, Value);
  Param := OSSL_PARAM_construct_int32('int32', @Value);
  Check(OSSL_PARAM_set_int32(@Param, Low(Integer)), 'Write int32');
  Check(OSSL_PARAM_get_int32(@Param, @Dest.Value), 'Read int32');
  Assert.AreEqual(Low(Integer), Dest.Value);
  Assert.AreEqual(Cardinal($DEADBEEF), Dest.Canary);
end;

procedure TTestInteropRegressions.ParamUnsignedLong;
var
  Value: Cardinal;
  Dest: record Value: Cardinal; Canary: Cardinal; end;
  Param: OSSL_PARAM;
begin
  Value := $FEDCBA98;
  Dest.Canary := $DEADBEEF;
  Param := OSSL_PARAM_construct_ulong('unsigned-long', @Value);
  Assert.AreEqual(NativeUInt(4), Param.data_size);
  Check(OSSL_PARAM_get_ulong(@Param, @Dest.Value), 'Read unsigned long');
  Assert.AreEqual(Value, Dest.Value);
  Assert.AreEqual(Cardinal($DEADBEEF), Dest.Canary);
  Check(OSSL_PARAM_set_ulong(@Param, High(Cardinal)), 'Write unsigned long');
  Assert.AreEqual(High(Cardinal), Value);
end;

procedure TTestInteropRegressions.ParamBigNumber;
var
  Bytes: array[0..3] of Byte;
  Param: OSSL_PARAM;
  Number: BIGNUM_ptr;
begin
  Bytes[0] := $78; Bytes[1] := $56; Bytes[2] := $34; Bytes[3] := $12;
  Param := OSSL_PARAM_construct_BN('number', @Bytes[0], SizeOf(Bytes));
  Assert.IsTrue(Param.data = @Bytes[0]);
  Assert.AreEqual(NativeUInt(4), Param.data_size);
  Number := nil;
  try
    Check(OSSL_PARAM_get_BN(@Param, @Number), 'Decode native-endian BN parameter');
    Assert.AreEqual(NativeUInt($12345678), BN_get_word(Number));
  finally
    BN_free(Number);
  end;
end;

procedure CheckAddress(Family: Integer; const Address: array of Byte; Port: Word);
var
  Addr: BIO_ADDR_ptr;
  Text: PAnsiChar;
  Raw: array[0..15] of Byte;
  Size: NativeUInt;
begin
  Addr := BIO_ADDR_new;
  Assert.IsNotNull(Addr);
  try
    Check(BIO_ADDR_rawmake(Addr, Family, @Address[0], Length(Address), htons(Port)), 'Create address');
    Assert.AreEqual(Family, BIO_ADDR_family(Addr));
    Assert.AreEqual(Integer(Port), Integer(ntohs(BIO_ADDR_rawport(Addr))));
    Size := SizeOf(Raw);
    Check(BIO_ADDR_rawaddress(Addr, @Raw[0], @Size), 'Read address bytes');
    Assert.AreEqual(NativeUInt(Length(Address)), Size);
    Assert.IsTrue(CompareMem(@Raw[0], @Address[0], Size));
    Text := BIO_ADDR_service_string(Addr, 1);
    Assert.IsNotNull(Text, 'Numeric service string exercises the CRT formatting bridge');
    try
      Assert.AreEqual(IntToStr(Port), string(AnsiString(Text)));
    finally
      OPENSSL_free(Text);
    end;
  finally
    BIO_ADDR_free(Addr);
  end;
end;

procedure TTestInteropRegressions.AddressIPv4;
begin CheckAddress(AF_INET, [127, 0, 0, 1], 443); end;

procedure TTestInteropRegressions.AddressIPv6;
begin CheckAddress(AF_INET6, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 65535); end;

procedure TTestInteropRegressions.BIOPairBackpressure;
var
  Left, Right: BIO_ptr;
  Source, Dest: array[0..15] of Byte;
  I: Integer;
begin
  Left := nil; Right := nil;
  Check(BIO_new_bio_pair(@Left, 8, @Right, 8), 'Create bounded BIO pair');
  try
    for I := 0 to High(Source) do Source[I] := Byte(I * 17);
    Assert.AreEqual(8, BIO_write(Left, @Source[0], SizeOf(Source)));
    Assert.IsTrue(BIO_write(Left, @Source[8], 8) <= 0, 'Full buffer must apply backpressure');
    Assert.IsTrue(BIO_should_retry(Left));
    Assert.AreEqual(8, BIO_read(Right, @Dest[0], 8));
    Assert.AreEqual(8, BIO_write(Left, @Source[8], 8));
    Assert.AreEqual(8, BIO_read(Right, @Dest[8], 8));
    Assert.IsTrue(CompareMem(@Source[0], @Dest[0], SizeOf(Source)));
    Assert.IsTrue(BIO_read(Right, @Dest[0], 1) <= 0);
    Assert.IsTrue(BIO_should_retry(Right));
  finally
    BIO_free(Right);
    BIO_free(Left);
  end;
end;

procedure TTestInteropRegressions.ASN1TimeBoundaries;
var
  Time: ASN1_TIME_ptr;
  BrokenDown: C_tm;
begin
  Time := ASN1_TIME_new;
  Assert.IsNotNull(Time);
  try
    Check(ASN1_TIME_set_string_X509(Time, '491231235959Z'), 'Last UTCTime year');
    Check(ASN1_TIME_to_tm(Time, @BrokenDown), 'Decode UTCTime');
    Assert.AreEqual(2049 - 1900, BrokenDown.tm_year);
    Check(ASN1_TIME_set_string_X509(Time, '20500101000000Z'), 'First GeneralizedTime year');
    Check(ASN1_TIME_to_tm(Time, @BrokenDown), 'Decode GeneralizedTime');
    Assert.AreEqual(2050 - 1900, BrokenDown.tm_year);
    Check(ASN1_TIME_set_string_X509(Time, '20240229010203Z'), 'Valid leap day');
    Assert.AreEqual(0, ASN1_TIME_set_string_X509(Time, '20230229010203Z'), 'Reject invalid leap day');
  finally
    ASN1_TIME_free(Time);
  end;
end;

procedure TTestInteropRegressions.IsolatedProviderReload;
var
  Ctx: OSSL_LIB_CTX_ptr;
  Provider: OSSL_PROVIDER_ptr;
  Digest: EVP_MD_ptr;
  I: Integer;
begin
  Ctx := OSSL_LIB_CTX_new;
  Assert.IsNotNull(Ctx);
  try
    for I := 1 to 3 do
    begin
      Provider := OSSL_PROVIDER_load(Ctx, 'default');
      Assert.IsNotNull(Provider);
      try
        Digest := EVP_MD_fetch(Ctx, 'SHA256', 'provider=default');
        Assert.IsNotNull(Digest);
        try
          Assert.AreEqual(32, EVP_MD_get_size(Digest));
        finally
          EVP_MD_free(Digest);
        end;
      finally
        Check(OSSL_PROVIDER_unload(Provider), 'Unload isolated provider');
      end;
    end;
    Assert.AreEqual(1, OSSL_PROVIDER_available(nil, 'default'), 'Global provider remains available');
  finally
    OSSL_LIB_CTX_free(Ctx);
  end;
end;

procedure CheckGCM(ModifyTag: Boolean);
var
  Ctx: EVP_CIPHER_CTX_ptr;
  Key, Plain, Cipher, Decoded, Tag: array[0..15] of Byte;
  IV: array[0..11] of Byte;
  Count, Last: Integer;
begin
  FillChar(Key, SizeOf(Key), 0);
  FillChar(IV, SizeOf(IV), 0);
  FillChar(Plain, SizeOf(Plain), 0);
  Ctx := EVP_CIPHER_CTX_new;
  Assert.IsNotNull(Ctx);
  try
    Check(EVP_EncryptInit_ex(Ctx, EVP_aes_128_gcm, nil, @Key[0], @IV[0]), 'GCM encrypt init');
    Check(EVP_EncryptUpdate(Ctx, @Cipher[0], @Count, @Plain[0], SizeOf(Plain)), 'GCM encrypt');
    Assert.AreEqual(16, Count);
    Check(EVP_EncryptFinal_ex(Ctx, @Cipher[0], @Last), 'GCM encrypt final');
    Assert.AreEqual(0, Last);
    Check(EVP_CIPHER_CTX_ctrl(Ctx, GCMGetTag, SizeOf(Tag), @Tag[0]), 'Get GCM tag');
    Assert.AreEqual('0388dace60b6a392f328c2b971b2fe78', Hex(Cipher, 16));
    Assert.AreEqual('ab6e47d42cec13bdf53a67b21257bddf', Hex(Tag, 16));
    if ModifyTag then Tag[0] := Tag[0] xor 1;
    Check(EVP_DecryptInit_ex(Ctx, EVP_aes_128_gcm, nil, @Key[0], @IV[0]), 'GCM decrypt init');
    Check(EVP_DecryptUpdate(Ctx, @Decoded[0], @Count, @Cipher[0], SizeOf(Cipher)), 'GCM decrypt');
    Check(EVP_CIPHER_CTX_ctrl(Ctx, GCMSetTag, SizeOf(Tag), @Tag[0]), 'Set GCM tag');
    Last := EVP_DecryptFinal_ex(Ctx, @Decoded[0], @Count);
    if ModifyTag then
      Assert.AreEqual(0, Last, 'Modified authentication tag must fail')
    else
    begin
      Check(Last, 'GCM authentication');
      Assert.IsTrue(CompareMem(@Plain[0], @Decoded[0], SizeOf(Plain)));
    end;
  finally
    EVP_CIPHER_CTX_free(Ctx);
  end;
end;

procedure TTestCryptoRegressions.AESGCMKnownVector;
begin CheckGCM(False); end;
procedure TTestCryptoRegressions.AESGCMRejectsModifiedTag;
begin CheckGCM(True); end;

procedure TTestCryptoRegressions.AESCBCRejectsInvalidPadding;
var
  Ctx: EVP_CIPHER_CTX_ptr;
  Key, IV, Plain: array[0..15] of Byte;
  Cipher, Decoded: array[0..47] of Byte;
  Count, Last: Integer;
begin
  FillChar(Key, SizeOf(Key), 0);
  FillChar(IV, SizeOf(IV), 0);
  FillChar(Plain, SizeOf(Plain), 0);
  Ctx := EVP_CIPHER_CTX_new;
  Assert.IsNotNull(Ctx);
  try
    Check(EVP_EncryptInit_ex(Ctx, EVP_aes_128_cbc, nil, @Key[0], @IV[0]), 'CBC encrypt init');
    Check(EVP_EncryptUpdate(Ctx, @Cipher[0], @Count, @Plain[0], SizeOf(Plain)), 'CBC encrypt');
    Check(EVP_EncryptFinal_ex(Ctx, @Cipher[Count], @Last), 'CBC padding');
    Assert.AreEqual(32, Count + Last);
    Cipher[15] := Cipher[15] xor $10; // The decrypted last padding byte becomes zero.
    Check(EVP_DecryptInit_ex(Ctx, EVP_aes_128_cbc, nil, @Key[0], @IV[0]), 'CBC decrypt init');
    Check(EVP_DecryptUpdate(Ctx, @Decoded[0], @Count, @Cipher[0], 32), 'CBC decrypt');
    Assert.AreEqual(0, EVP_DecryptFinal_ex(Ctx, @Decoded[Count], @Last));
    Assert.IsTrue(ERR_get_error <> 0, 'Invalid padding must populate the error queue');
  finally
    EVP_CIPHER_CTX_free(Ctx);
  end;
end;

procedure TTestCryptoRegressions.PBKDF2KnownVector;
var Output: array[0..31] of Byte;
begin
  Check(PKCS5_PBKDF2_HMAC('password', 8, PByte(PAnsiChar('salt')), 4, 1,
    EVP_sha256, SizeOf(Output), @Output[0]), 'PBKDF2-HMAC-SHA256');
  Assert.AreEqual('120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b', Hex(Output, 32));
end;

procedure TTestCryptoRegressions.RSASignatureRejectsModifiedMessage;
var
  KeyCtx: EVP_PKEY_CTX_ptr;
  Key: EVP_PKEY_ptr;
  DigestCtx: EVP_MD_CTX_ptr;
  Signature: TBytes;
  Size: NativeUInt;
  Message: AnsiString;
begin
  KeyCtx := EVP_PKEY_CTX_new_from_name(nil, 'RSA', nil);
  Assert.IsNotNull(KeyCtx);
  try
    Check(EVP_PKEY_keygen_init(KeyCtx), 'RSA keygen init');
    Check(EVP_PKEY_CTX_set_rsa_keygen_bits(KeyCtx, 2048), 'RSA key size');
    Key := nil;
    Check(EVP_PKEY_generate(KeyCtx, @Key), 'RSA key generation');
    try
      DigestCtx := EVP_MD_CTX_new;
      Assert.IsNotNull(DigestCtx);
      try
        Message := 'binary'#0'message';
        Check(EVP_DigestSignInit(DigestCtx, nil, EVP_sha256, nil, Key), 'RSA sign init');
        Size := 0;
        Check(EVP_DigestSign(DigestCtx, nil, @Size, PByte(PAnsiChar(Message)), Length(Message)), 'RSA signature size');
        SetLength(Signature, Size);
        Check(EVP_DigestSign(DigestCtx, @Signature[0], @Size, PByte(PAnsiChar(Message)), Length(Message)), 'RSA signature');
        Check(EVP_DigestVerifyInit(DigestCtx, nil, EVP_sha256, nil, Key), 'RSA verify init');
        Check(EVP_DigestVerify(DigestCtx, @Signature[0], Size, PByte(PAnsiChar(Message)), Length(Message)), 'RSA signature verify');
        Message[1] := 'B';
        Check(EVP_DigestVerifyInit(DigestCtx, nil, EVP_sha256, nil, Key), 'RSA negative verify init');
        Assert.AreEqual(0, EVP_DigestVerify(DigestCtx, @Signature[0], Size, PByte(PAnsiChar(Message)), Length(Message)));
      finally
        EVP_MD_CTX_free(DigestCtx);
      end;
    finally
      EVP_PKEY_free(Key);
    end;
  finally
    EVP_PKEY_CTX_free(KeyCtx);
  end;
end;

function Derive(Key, Peer: EVP_PKEY_ptr): TBytes;
var Ctx: EVP_PKEY_CTX_ptr; Size: NativeUInt;
begin
  Ctx := EVP_PKEY_CTX_new_from_pkey(nil, Key, nil);
  Assert.IsNotNull(Ctx);
  try
    Check(EVP_PKEY_derive_init(Ctx), 'ECDH derive init');
    Check(EVP_PKEY_derive_set_peer(Ctx, Peer), 'ECDH set peer');
    Size := 0;
    Check(EVP_PKEY_derive(Ctx, nil, @Size), 'ECDH size');
    SetLength(Result, Size);
    Check(EVP_PKEY_derive(Ctx, @Result[0], @Size), 'ECDH derive');
    SetLength(Result, Size);
  finally
    EVP_PKEY_CTX_free(Ctx);
  end;
end;

procedure TTestCryptoRegressions.ECDHSharedSecret;
var Left, Right: EVP_PKEY_ptr; A, B: TBytes;
begin
  Left := EVP_PKEY_Q_keygen(nil, nil, 'EC', PAnsiChar('P-256'));
  Assert.IsNotNull(Left);
  try
    Right := EVP_PKEY_Q_keygen(nil, nil, 'EC', PAnsiChar('P-256'));
    Assert.IsNotNull(Right);
    try
      A := Derive(Left, Right);
      B := Derive(Right, Left);
      Assert.AreEqual(NativeInt(32), Length(A));
      Assert.AreEqual(Length(A), Length(B));
      Assert.IsTrue(CompareMem(@A[0], @B[0], Length(A)));
    finally
      EVP_PKEY_free(Right);
    end;
  finally
    EVP_PKEY_free(Left);
  end;
end;

procedure TTestCryptoRegressions.ProviderHMAC;
var
  Mac: EVP_MAC_ptr;
  Ctx: EVP_MAC_CTX_ptr;
  Params: array[0..1] of OSSL_PARAM;
  Output: array[0..31] of Byte;
  Size: NativeUInt;
  Digest: array[0..6] of AnsiChar;
begin
  Mac := EVP_MAC_fetch(nil, 'HMAC', nil);
  Assert.IsNotNull(Mac);
  try
    Ctx := EVP_MAC_CTX_new(Mac);
    Assert.IsNotNull(Ctx);
    try
      Move(PAnsiChar('SHA256')^, Digest[0], SizeOf(Digest));
      Params[0] := OSSL_PARAM_construct_utf8_string('digest', @Digest[0], 0);
      Params[1] := OSSL_PARAM_construct_end;
      Check(EVP_MAC_init(Ctx, PByte(PAnsiChar('Jefe')), 4, @Params[0]), 'Provider HMAC init');
      Check(EVP_MAC_update(Ctx, PByte(PAnsiChar('what do ya want for nothing?')), 28), 'Provider HMAC update');
      Check(EVP_MAC_final(Ctx, @Output[0], @Size, SizeOf(Output)), 'Provider HMAC final');
      Assert.AreEqual(NativeUInt(32), Size);
      Assert.AreEqual('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843', Hex(Output, 32));
    finally
      EVP_MAC_CTX_free(Ctx);
    end;
  finally
    EVP_MAC_free(Mac);
  end;
end;

type
  TTLSConnection = class
  private
    FClientCtx, FServerCtx: SSL_CTX_ptr;
    FKey: EVP_PKEY_ptr;
    FCert: X509_ptr;
  public
    Client, Server: SSL_ptr;
    LastError: string;
    constructor Create(Version: Integer; TrustServer: Boolean = True);
    destructor Destroy; override;
    function Handshake: Boolean;
    procedure Exchange;
  end;

constructor TTLSConnection.Create(Version: Integer; TrustServer: Boolean);
var Name: X509_NAME_ptr; ClientBIO, ServerBIO: BIO_ptr;
begin
  inherited Create;
  FKey := EVP_PKEY_Q_keygen(nil, nil, 'EC', PAnsiChar('P-256'));
  Assert.IsNotNull(FKey);
  FCert := X509_new;
  Assert.IsNotNull(FCert);
  Check(X509_set_version(FCert, 2), 'Certificate version');
  Check(ASN1_INTEGER_set(X509_get_serialNumber(FCert), 42), 'Certificate serial');
  Assert.IsNotNull(X509_gmtime_adj(X509_getm_notBefore(FCert), -60));
  Assert.IsNotNull(X509_gmtime_adj(X509_getm_notAfter(FCert), 3600));
  Check(X509_set_pubkey(FCert, FKey), 'Certificate public key');
  Name := X509_get_subject_name(FCert);
  Check(X509_NAME_add_entry_by_txt(Name, 'CN', $1001, PByte(PAnsiChar('localhost')), -1, -1, 0), 'Certificate name');
  Check(X509_set_issuer_name(FCert, Name), 'Certificate issuer');
  Assert.IsTrue(X509_sign(FCert, FKey, EVP_sha256) > 0);
  FClientCtx := SSL_CTX_new(TLS_client_method);
  Assert.IsNotNull(FClientCtx);
  FServerCtx := SSL_CTX_new(TLS_server_method);
  Assert.IsNotNull(FServerCtx);
  Check(SSL_CTX_set_min_proto_version(FClientCtx, Version), 'Client min protocol');
  Check(SSL_CTX_set_max_proto_version(FClientCtx, Version), 'Client max protocol');
  Check(SSL_CTX_set_min_proto_version(FServerCtx, Version), 'Server min protocol');
  Check(SSL_CTX_set_max_proto_version(FServerCtx, Version), 'Server max protocol');
  Check(SSL_CTX_use_certificate(FServerCtx, FCert), 'Server certificate');
  Check(SSL_CTX_use_PrivateKey(FServerCtx, FKey), 'Server private key');
  SSL_CTX_set_verify(FClientCtx, SSL_VERIFY_PEER, nil);
  if TrustServer then
    Check(X509_STORE_add_cert(SSL_CTX_get_cert_store(FClientCtx), FCert), 'Trust test certificate');
  Client := SSL_new(FClientCtx);
  Assert.IsNotNull(Client);
  Server := SSL_new(FServerCtx);
  Assert.IsNotNull(Server);
  ClientBIO := nil; ServerBIO := nil;
  Check(BIO_new_bio_pair(@ClientBIO, 16384, @ServerBIO, 16384), 'TLS BIO pair');
  SSL_set_bio(Client, ClientBIO, ClientBIO);
  SSL_set_bio(Server, ServerBIO, ServerBIO);
  SSL_set_connect_state(Client);
  SSL_set_accept_state(Server);
end;

destructor TTLSConnection.Destroy;
begin
  SSL_free(Server);
  SSL_free(Client);
  SSL_CTX_free(FServerCtx);
  SSL_CTX_free(FClientCtx);
  X509_free(FCert);
  EVP_PKEY_free(FKey);
  inherited;
end;

function TTLSConnection.Handshake: Boolean;
var
  Step, ClientResult, ServerResult, Error: Integer;
  ClientDone, ServerDone: Boolean;
begin
  ClientDone := False; ServerDone := False;
  for Step := 1 to MaxHandshakeSteps do
  begin
    if not ClientDone then
    begin
      ERR_clear_error;
      ClientResult := SSL_do_handshake(Client);
      ClientDone := ClientResult = 1;
      if not ClientDone then
      begin
        Error := SSL_get_error(Client, ClientResult);
        if (Error <> SSL_ERROR_WANT_READ) and (Error <> SSL_ERROR_WANT_WRITE) then
        begin
          LastError := 'client: ' + string(AnsiString(ERR_error_string(ERR_peek_last_error, nil)));
          Exit(False);
        end;
      end;
    end;
    if not ServerDone then
    begin
      ERR_clear_error;
      ServerResult := SSL_do_handshake(Server);
      ServerDone := ServerResult = 1;
      if not ServerDone then
      begin
        Error := SSL_get_error(Server, ServerResult);
        if (Error <> SSL_ERROR_WANT_READ) and (Error <> SSL_ERROR_WANT_WRITE) then
        begin
          LastError := 'server: ' + string(AnsiString(ERR_error_string(ERR_peek_last_error, nil)));
          Exit(False);
        end;
      end;
    end;
    if ClientDone and ServerDone then Exit(True);
  end;
  Assert.Fail('TLS handshake exceeded its bounded step budget');
  Result := False;
end;

procedure TTLSConnection.Exchange;
const Payload: array[0..7] of Byte = (0, $FF, 1, $80, 0, 2, 3, 4);
var Received: array[0..7] of Byte; Written, ReadCount: NativeUInt;
begin
  Check(SSL_write_ex(Client, @Payload[0], SizeOf(Payload), @Written), 'Client application data');
  Assert.AreEqual(NativeUInt(SizeOf(Payload)), Written);
  Check(SSL_read_ex(Server, @Received[0], SizeOf(Received), @ReadCount), 'Server application data');
  Assert.AreEqual(Written, ReadCount);
  Assert.IsTrue(CompareMem(@Payload[0], @Received[0], SizeOf(Payload)));
  Check(SSL_write_ex(Server, @Received[0], ReadCount, @Written), 'Server application data');
  Check(SSL_read_ex(Client, @Received[0], SizeOf(Received), @ReadCount), 'Client application data');
  Assert.AreEqual(NativeUInt(SizeOf(Payload)), ReadCount);
  Assert.IsTrue(CompareMem(@Payload[0], @Received[0], SizeOf(Payload)));
  Assert.AreEqual(0, SSL_get_verify_result(Client));
end;

procedure CheckTLS(Version: Integer; const VersionName: string);
var Connection: TTLSConnection;
begin
  Connection := TTLSConnection.Create(Version);
  try
    Assert.IsTrue(Connection.Handshake, 'Verified TLS handshake: ' + Connection.LastError);
    Assert.AreEqual(VersionName, string(AnsiString(SSL_get_version(Connection.Client))));
    Assert.IsNotNull(SSL_get_current_cipher(Connection.Client));
    Connection.Exchange;
  finally
    Connection.Free;
  end;
end;

procedure TTestTLSRegressions.TLS12HandshakeAndData;
begin CheckTLS(TLS1_2_VERSION, 'TLSv1.2'); end;
procedure TTestTLSRegressions.TLS13HandshakeAndData;
begin CheckTLS(TLS1_3_VERSION, 'TLSv1.3'); end;

procedure TTestTLSRegressions.RejectUntrustedCertificate;
var Connection: TTLSConnection;
begin
  Connection := TTLSConnection.Create(TLS1_2_VERSION, False);
  try
    Assert.IsFalse(Connection.Handshake, 'A self-signed certificate without a trust anchor must fail');
    Assert.IsTrue(SSL_get_verify_result(Connection.Client) <> 0);
  finally
    Connection.Free;
  end;
end;

procedure TTestTLSRegressions.DuplicateNegotiatedSession;
var Connection: TTLSConnection; Session, CopySession: SSL_SESSION_ptr;
begin
  Connection := TTLSConnection.Create(TLS1_2_VERSION);
  try
    Assert.IsTrue(Connection.Handshake);
    Session := SSL_get1_session(Connection.Client);
    Assert.IsNotNull(Session, 'A completed TLS 1.2 handshake must establish a session');
    try
      CopySession := SSL_SESSION_dup(Session);
      Assert.IsNotNull(CopySession);
      try
        Assert.IsTrue(CopySession <> Session);
        Assert.AreEqual(TLS1_2_VERSION, SSL_SESSION_get_protocol_version(CopySession));
      finally
        SSL_SESSION_free(CopySession);
      end;
    finally
      SSL_SESSION_free(Session);
    end;
  finally
    Connection.Free;
  end;
end;

procedure TTestTLSRegressions.BidirectionalShutdown;
var Connection: TTLSConnection;
begin
  Connection := TTLSConnection.Create(TLS1_2_VERSION);
  try
    Assert.IsTrue(Connection.Handshake);
    Connection.Exchange;
    Assert.AreEqual(0, SSL_shutdown(Connection.Client), 'Send first close_notify');
    Assert.IsTrue(SSL_shutdown(Connection.Server) >= 0, 'Send peer close_notify');
    Check(SSL_shutdown(Connection.Client), 'Complete bidirectional TLS shutdown');
    Check(SSL_shutdown(Connection.Server), 'Complete peer TLS shutdown');
  finally
    Connection.Free;
  end;
end;

{$IFNDEF OPENSSL_3X}
procedure TTestSKeyRegressions.Setup;
begin Initialize; end;
procedure TTestSKeyRegressions.TearDown;
begin ERR_clear_error; end;

procedure TTestSKeyRegressions.ManagementReferenceCounting;
var Management: EVP_SKEYMGMT_ptr;
begin
  Management := EVP_SKEYMGMT_fetch(nil, 'GENERIC-SECRET', nil);
  Assert.IsNotNull(Management);
  try
    Check(EVP_SKEYMGMT_up_ref(Management), 'SKEYMGMT up_ref');
    EVP_SKEYMGMT_free(Management);
    Check(EVP_SKEYMGMT_is_a(Management, 'GENERIC-SECRET'), 'SKEYMGMT survives release of additional reference');
    Assert.IsNotNull(EVP_SKEYMGMT_get0_provider(Management));
  finally
    EVP_SKEYMGMT_free(Management);
  end;
end;

procedure TTestSKeyRegressions.RawKeyReferenceCounting;
var Key: EVP_SKEY_ptr; Bytes: array[0..15] of Byte; Raw: PByte; Size: NativeUInt; I: Integer;
begin
  for I := 0 to High(Bytes) do Bytes[I] := Byte(I * 17);
  Key := EVP_SKEY_import_raw_key(nil, 'AES-128', @Bytes[0], SizeOf(Bytes), nil);
  Assert.IsNotNull(Key);
  try
    Check(EVP_SKEY_up_ref(Key), 'SKEY up_ref');
    EVP_SKEY_free(Key);
    Raw := nil; Size := 0;
    Check(EVP_SKEY_get0_raw_key(Key, @Raw, @Size), 'Export borrowed raw SKEY');
    Assert.AreEqual(NativeUInt(SizeOf(Bytes)), Size);
    Assert.IsNotNull(Raw);
    Assert.IsTrue(CompareMem(@Raw[0], @Bytes[0], Size));
  finally
    EVP_SKEY_free(Key);
  end;
end;
{$ENDIF}

initialization
  TDUnitX.RegisterTestFixture(TTestInteropRegressions);
  TDUnitX.RegisterTestFixture(TTestCryptoRegressions);
  TDUnitX.RegisterTestFixture(TTestTLSRegressions);
{$IFNDEF OPENSSL_3X}
  TDUnitX.RegisterTestFixture(TTestSKeyRegressions);
{$ENDIF}

end.
