/// Roger Plus NFC Services Library
/// 
/// A production-ready library for secure NFC MIFARE Plus card operations.
/// Provides authentication, data reading, and binary conversion utilities
/// with comprehensive error handling and security measures.
/// 
/// Features:
/// - Secure AES-128 encryption/decryption
/// - MIFARE Plus authentication protocol
/// - Data reading with encryption support
/// - Binary conversion utilities
/// - Comprehensive error handling
/// - Debug logging support
/// 
/// Usage:
/// ```dart
/// final nfcService = PlusNfcServices(debugMode: false);
/// final result = await nfcService.readPlus(...);
/// ```

import 'dart:async';
import 'dart:math';

import 'package:convert/convert.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:flutter/services.dart';
import 'package:flutter_nfc_kit/flutter_nfc_kit.dart';
import 'package:pointycastle/export.dart';

// =============================================================================
// EXCEPTIONS AND ERROR TYPES
// =============================================================================

/// Custom exception for NFC operations
class NfcException implements Exception {
  final String message;
  final String? errorCode;
  final dynamic originalError;

  const NfcException(this.message, {this.errorCode, this.originalError});

  @override
  String toString() => 'NfcException: $message${errorCode != null ? ' ($errorCode)' : ''}';
}

/// Custom exception for cryptographic operations
class CryptoException implements Exception {
  final String message;
  final dynamic originalError;

  const CryptoException(this.message, {this.originalError});

  @override
  String toString() => 'CryptoException: $message';
}

/// Custom exception for MIFARE Plus protocol errors
class PlusException implements Exception {
  final String message;
  final String? statusCode;
  final dynamic originalError;

  const PlusException(this.message, {this.statusCode, this.originalError});

  @override
  String toString() => '$message${statusCode != null ? ' (Status: $statusCode)' : ''}';
}

// =============================================================================
// PRIVATE CRYPTOGRAPHIC SERVICES
// =============================================================================

/// Private cryptographic services for NFC MIFARE Plus operations.
/// 
/// This class handles all cryptographic operations including:
/// - AES-128 encryption/decryption in CBC mode
/// - Secure random number generation
/// - Data rotation for Plus protocol
/// - AES-CMAC computation
/// 
/// Only accessible within this library for security purposes.
class _CryptoNfcServices {
  static const int _aesKeySize = 16;
  static const int _aesBlockSize = 16;
  static const int _randomSize = 16;

  /// Encrypts data using AES-128 in CBC mode.
  /// 
  /// [data] The data to encrypt (must not be null)
  /// [keyBytes] The encryption key (must be exactly 16 bytes)
  /// [ivBytes] The initialization vector (must be exactly 16 bytes)
  /// 
  /// Returns encrypted data as Uint8List
  /// 
  /// Throws:
  /// - [ArgumentError] if parameters are invalid
  /// - [CryptoException] if encryption fails
  Uint8List aesEncrypt(Uint8List data, Uint8List keyBytes, {required Uint8List ivBytes}) {
    _validateCryptoInput(data, keyBytes, ivBytes, 'encryption');
    
    try {
      final key = encrypt.Key(keyBytes);
      final iv = encrypt.IV(ivBytes);
      final encrypter = encrypt.Encrypter(
        encrypt.AES(key, mode: encrypt.AESMode.cbc, padding: null),
      );
      
      final encrypted = encrypter.encryptBytes(data, iv: iv);
      return Uint8List.fromList(encrypted.bytes);
    } catch (e) {
      throw CryptoException('AES encryption failed', originalError: e);
    }
  }

  /// Decrypts data using AES-128 in CBC mode.
  /// 
  /// [data] The encrypted data to decrypt (must not be null)
  /// [keyBytes] The decryption key (must be exactly 16 bytes)
  /// [ivBytes] The initialization vector (must be exactly 16 bytes)
  /// 
  /// Returns decrypted data as Uint8List
  /// 
  /// Throws:
  /// - [ArgumentError] if parameters are invalid
  /// - [CryptoException] if decryption fails
  Uint8List aesDecrypt(Uint8List data, Uint8List keyBytes, {required Uint8List ivBytes}) {
    _validateCryptoInput(data, keyBytes, ivBytes, 'decryption');
    
    try {
      final key = encrypt.Key(keyBytes);
      final iv = encrypt.IV(ivBytes);
      final encrypter = encrypt.Encrypter(
        encrypt.AES(key, mode: encrypt.AESMode.cbc, padding: null),
      );
      
      final decrypted = encrypter.decryptBytes(encrypt.Encrypted(data), iv: iv);
      return Uint8List.fromList(decrypted);
    } catch (e) {
      throw CryptoException('AES decryption failed', originalError: e);
    }
  }

  /// Generates a cryptographically secure random byte array.
  /// 
  /// [size] Size of the random data (defaults to 16 bytes for MIFARE Plus)
  /// 
  /// Returns a secure random Uint8List
  /// 
  /// Throws [ArgumentError] if size is invalid
  Uint8List generateSecureRandom([int size = _randomSize]) {
    if (size <= 0) {
      throw ArgumentError('Size must be positive, got: $size');
    }
    
    final secureRandom = Random.secure();
    return Uint8List.fromList(List.generate(size, (_) => secureRandom.nextInt(256)));
  }

  /// Rotates a byte array one position to the left.
  /// Used in MIFARE Plus authentication protocol.
  /// 
  /// [data] The byte array to rotate (must not be null or empty)
  /// 
  /// Returns rotated byte array
  /// 
  /// Throws [ArgumentError] if data is invalid
  Uint8List rotateLeft(Uint8List data) {
    if (data.isEmpty) {
      throw ArgumentError('Data cannot be empty');
    }
    
    return Uint8List.fromList([...data.sublist(1), data[0]]);
  }

  /// Computes AES-CMAC with specified output size.
  /// 
  /// [hexKey] Hexadecimal string representation of the key
  /// [hexData] Hexadecimal string representation of the data
  /// [outputBits] Output size in bits (64 or 128)
  /// 
  /// Returns uppercase hexadecimal string of the CMAC
  /// 
  /// Throws:
  /// - [ArgumentError] if parameters are invalid
  /// - [CryptoException] if computation fails
  static String computeAesCmac(String hexKey, String hexData, int outputBits) {
    if (hexKey.isEmpty || hexData.isEmpty) {
      throw ArgumentError('Key and data cannot be empty');
    }
    if (outputBits != 64 && outputBits != 128) {
      throw ArgumentError('Output bits must be 64 or 128, got: $outputBits');
    }
    if (!_isValidHex(hexKey) || !_isValidHex(hexData)) {
      throw ArgumentError('Key and data must be valid hexadecimal strings');
    }
    
    try {
      final keyBytes = Uint8List.fromList(hex.decode(hexKey));
      final dataBytes = Uint8List.fromList(hex.decode(hexData));
      
      final cmac = CMac(BlockCipher('AES'), outputBits);
      final keyParam = KeyParameter(keyBytes);
      
      cmac.init(keyParam);
      cmac.update(dataBytes, 0, dataBytes.length);
      
      final macBytes = Uint8List(cmac.macSize);
      cmac.doFinal(macBytes, 0);
      
      return hex.encode(macBytes).toUpperCase();
    } catch (e) {
      throw CryptoException('AES-CMAC-$outputBits computation failed', originalError: e);
    }
  }

  /// Converts an integer to a 4-character (2-byte) little-endian hex string.
  static String intToLittleEndianHex(int value) {
    final hexString = value.toRadixString(16).padLeft(4, '0');
    // Swap bytes for little endian
    return hexString.substring(2, 4) + hexString.substring(0, 2);
  }

  /// Validates cryptographic input parameters.
  void _validateCryptoInput(Uint8List data, Uint8List keyBytes, Uint8List ivBytes, String operation) {
    ArgumentError.checkNotNull(data, 'data');
    ArgumentError.checkNotNull(keyBytes, 'keyBytes');
    ArgumentError.checkNotNull(ivBytes, 'ivBytes');
    
    if (keyBytes.length != _aesKeySize) {
      throw ArgumentError('Key must be exactly $_aesKeySize bytes for AES-128, got: ${keyBytes.length}');
    }
    if (ivBytes.length != _aesBlockSize) {
      throw ArgumentError('IV must be exactly $_aesBlockSize bytes, got: ${ivBytes.length}');
    }
    if (data.isEmpty) {
      throw ArgumentError('Data cannot be empty for $operation');
    }
  }

  /// Validates if a string contains only hexadecimal characters.
  static bool _isValidHex(String value) {
    return RegExp(r'^[0-9A-Fa-f]+$').hasMatch(value);
  }
}

// =============================================================================
// MIFARE PLUS NFC SERVICES
// =============================================================================

/// Production-ready MIFARE Plus NFC Services for secure card operations.
/// 
/// This service provides:
/// - NFC availability checking
/// - MIFARE Plus sector selection and authentication
/// - Encrypted data reading from blocks
/// - Comprehensive error handling and logging
/// 
/// Example usage:
/// ```dart
/// final service = PlusNfcServices(debugMode: false);
/// 
/// final result = await service.readPlus(
///   sector: '0',
///   block: '1',
///   keyType: 'Key A',
///   keyHex: '00000000000000000000000000000000',
/// );
/// ```
class PlusNfcServices {
  static const int _timeout = 7;
  static const String _successStatus = '90';
  static const int _aesKeySize = 16;
  static const int _expectedEncryptedRndBLength = 32;
  static const int _expectedResponseLength = 64;
  static const int _minimumDecryptedResponseLength = 24;
  
  final _CryptoNfcServices _crypto = _CryptoNfcServices();
  final bool debugMode;

  /// Creates a new instance of PlusNfcServices.
  /// 
  /// [debugMode] If true, enables detailed debug logging.
  ///            Should be false in production for security.
  PlusNfcServices({this.debugMode = false});

  // =============================================================================
  // PUBLIC API METHODS
  // =============================================================================

  /// Checks if NFC is available and enabled on the device.
  /// 
  /// Returns error codes indicating the NFC status:
  /// - "00": NFC is available and enabled (success)
  /// - "E1": NFC is available but disabled by user
  /// - "E2": NFC is not supported on this device
  /// - "E3": Unknown NFC availability status
  /// - "E4": Platform error occurred
  /// - "E5": Unexpected error occurred
  /// 
  /// Never throws exceptions - returns error codes for all conditions.
  Future<String> isNfcAvailable() async {
    try {
      final nfcAvailability = await FlutterNfcKit.nfcAvailability;
      
      switch (nfcAvailability) {
        case NFCAvailability.available:
          _debugPrint("✅ NFC is available and enabled");
          return "00";
        case NFCAvailability.disabled:
          _debugPrint("⚠️ NFC is available but disabled by user");
          return "E1";
        case NFCAvailability.not_supported:
          _debugPrint("❌ NFC is not supported on this device");
          return "E2";
      }
    } on PlatformException catch (e) {
      _debugPrint("❌ Platform error checking NFC: ${e.message} (${e.code})");
      return "E4";
    } catch (e, stackTrace) {
      _debugPrint("❌ Unexpected error checking NFC: $e");
      if (debugMode) _debugPrint("Stack trace: $stackTrace");
      return "E5";
    }
  }

  /// Main entry point for MIFARE Plus card processing with encrypted connection.
  /// 
  /// Performs the complete MIFARE Plus read operation:
  /// 1. Validates all input parameters
  /// 2. Polls for NFC card
  /// 3. Authenticates with the sector
  /// 4. Reads and decrypts block data
  /// 
  /// Parameters:
  /// - [sector] Sector number as string (0-based)
  /// - [block] Block number within sector as string (0-based)
  /// - [keyType] Authentication key type ("Key A" or "Key B")
  /// - [keyHex] Authentication key as hex string (32 characters)
  /// - [isPlaintext] Whether the communication is plaintext (default: true)
  /// - [requiresMacOnResponse] Whether MAC is required on the response (default: false)
  /// 
  /// Note: MAC on command is always enabled for security.
  /// 
  /// Returns the processed data as hex string or error message.
  /// 
  /// Note: This method catches all exceptions and returns error messages
  /// instead of throwing, making it safe for UI integration.
  Future<String> readPlus(
    String sector,
    String block,
    String keyType,
    String keyHex, {
    bool isPlaintext = true,
    bool requiresMacOnResponse = false,
  }) async {
    try {
      _validateReadPlusParameters(sector, block, keyType, keyHex);

      final nfcStatus = await isNfcAvailable();
      if (nfcStatus != "00") {
        final errorMessage = _getNfcErrorMessage(nfcStatus);
        throw NfcException("NFC is not available: $errorMessage");
      }

      final result = await _performPlusRead(
        sector, 
        block, 
        keyType, 
        keyHex,
        isPlaintext: isPlaintext,
        requiresMacOnResponse: requiresMacOnResponse,
      );

      _debugPrint("✅ MIFARE Plus read operation completed successfully");
      return result;
      
    } on ArgumentError catch (e) {
      final error = "Invalid parameter: $e";
      _debugPrint("❌ $error");
      return "Error: $error";
    } on TimeoutException catch (e) {
      final error = "Operation timed out: $e";
      _debugPrint("❌ $error");
      return "Error: $error";
    } on NfcException catch (e) {
      _debugPrint("❌ NFC error: $e");
      return "Error: $e";
    } on PlusException catch (e) {
      _debugPrint("❌ MIFARE Plus error: $e");
      return "Error: $e";
    } on CryptoException catch (e) {
      _debugPrint("❌ Crypto error: $e");
      return "Error: $e";
    } catch (e, stackTrace) {
      _debugPrint("❌ Unexpected error: $e");
      if (debugMode) _debugPrint("Stack trace: $stackTrace");
      return "Error: Unexpected error occurred - $e";
    } finally {
      await _finishNfcSession();
    }
  }

  // =============================================================================
  // PRIVATE IMPLEMENTATION METHODS
  // =============================================================================

  /// Performs the complete MIFARE Plus read operation.
  /// MAC on command is always enabled for security.
  Future<String> _performPlusRead(
    String sector,
    String block,
    String keyType,
    String keyHex, {
    bool isPlaintext = true,
    bool requiresMacOnResponse = false,
  }) async {
    final sectorNumber = int.parse(sector);
    final blockNumber = int.parse(block);
    final authenticationKey = Uint8List.fromList(hex.decode(keyHex));
    final initializationVector = Uint8List.fromList(List.filled(_aesKeySize, 0));
    
    // Poll for NFC card
    await _pollForCard();
    
    // Authenticate with sector
    final (plainRandomA, plainRandomB, transactionIdentifier) = await _authenticateWithSector(sectorNumber, keyType, authenticationKey, initializationVector);
    
    // Generate session keys and read data
    final sessionKeys = _generateSessionKeys(plainRandomA, plainRandomB);
    
    return await _readEncryptedBlockData(
      sectorNumber, 
      blockNumber, 
      sessionKeys, 
      transactionIdentifier, 
      authenticationKey, 
      initializationVector,
      isPlaintext: isPlaintext,
      requiresMacOnResponse: requiresMacOnResponse,
    );
  }

  /// Polls for an NFC card with timeout.
  Future<NFCTag> _pollForCard() async {
    _debugPrint("🔍 Starting NFC polling...");
    
    final nfcTag = await FlutterNfcKit.poll(
      timeout: const Duration(seconds: _timeout),
      iosMultipleTagMessage: "Multiple tags found!",
      iosAlertMessage: "Scan your MIFARE Plus card",
    ).timeout(const Duration(seconds: _timeout));
    
    _debugPrint("📱 Tag detected: ${nfcTag.type}");
    _debugPrint("📋 Tag standard: ${nfcTag.standard}");
    _debugPrint("🆔 Tag ID: ${nfcTag.id}");
    
    return nfcTag;
  }

  /// Authenticates with the MIFARE Plus sector using AES.
  Future<(Uint8List, Uint8List, Uint8List)> _authenticateWithSector(
    int sectorNumber, 
    String keyType, 
    Uint8List authenticationKey, 
    Uint8List initializationVector,
  ) async {
    _debugPrint("🔐 Starting MIFARE Plus authentication...");
    
    // Step 1: Send authentication command
    final authenticateCommand = _buildAuthenticateCmd(sectorNumber, keyType);
    _debugPrint("📤 Auth command: $authenticateCommand");
    
    final response = await _transceiveCommand(authenticateCommand);
    final errorCheck = _checkTransceiveError(response, 'authentication');
    if (errorCheck != null) {
      throw PlusException(errorCheck);
    }
    
    // Step 2: Decrypt RandomB
    final encryptedRandomBHex = response.substring(2);
    final plainRandomB = _decryptRandomB(encryptedRandomBHex, authenticationKey, initializationVector);
    _debugPrint("🎲 Decrypted RandomB: ${hex.encode(plainRandomB)}");
    
    // Step 3: Generate RandomA and create response
    final plainRandomA = _crypto.generateSecureRandom(_aesKeySize);
    final rotatedRandomB = _crypto.rotateLeft(plainRandomB);
    final dataToEncrypt = Uint8List.fromList([...plainRandomA, ...rotatedRandomB]);
    final encryptedRandomAB = _crypto.aesEncrypt(dataToEncrypt, authenticationKey, ivBytes: initializationVector);
    
    // Step 4: Send encrypted response
    final authResponseCommand = "72${hex.encode(encryptedRandomAB)}";
    final authResponse = await _transceiveCommand(authResponseCommand);
    final errorCheck2 = _checkTransceiveError(authResponse, 'second authentication phase');
    if (errorCheck2 != null) {
      throw PlusException(errorCheck2);
    }
    
    // Step 5: Verify response and extract TI
    final dataToDecrypt = authResponse.startsWith(_successStatus) 
        ? authResponse.substring(2) 
        : authResponse;
    
    if (dataToDecrypt.length != _expectedResponseLength) {
      throw PlusException('Unexpected response length after 0x72 command: ${dataToDecrypt.length}');
    }
    
    final decryptedAuthResponse = _crypto.aesDecrypt(
      Uint8List.fromList(hex.decode(dataToDecrypt)),
      authenticationKey,
      ivBytes: initializationVector,
    );
    
    if (decryptedAuthResponse.length < _minimumDecryptedResponseLength) {
      throw PlusException('Decrypted response too short: ${decryptedAuthResponse.length}');
    }
    
    final transactionIdentifier = decryptedAuthResponse.sublist(0, 4);
    _debugPrint("🔑 Authentication successful, TI: ${hex.encode(transactionIdentifier)}");
    
    return (plainRandomA, plainRandomB, transactionIdentifier);
  }

  /// Reads encrypted block data using session keys.
  /// MAC on command is always enabled for security.
  Future<String> _readEncryptedBlockData(
    int sectorNumber,
    int blockNumber,
    Map<String, Uint8List> sessionKeys,
    Uint8List transactionIdentifier,
    Uint8List authenticationKey,
    Uint8List initializationVector, {
    bool isPlaintext = false,
    bool requiresMacOnResponse = false,
  }) async {
    _debugPrint("📖 Reading encrypted block data...");
    
    // Determine command code based on plaintext and MAC response requirements
    // MAC on command is always enabled for security
    final commandCode = _getReadCommandCode(
      isPlaintext: isPlaintext,
      requiresMacOnResponse: requiresMacOnResponse,
    );
    
    final encryptedMacKey = _crypto.aesEncrypt(sessionKeys['Kmac']!, authenticationKey, ivBytes: initializationVector);
    final encryptedEncryptionKey = _crypto.aesEncrypt(sessionKeys['Kenc']!, authenticationKey, ivBytes: initializationVector);
    
    final transactionIdentifierHex = hex.encode(transactionIdentifier);
    final sectorAddressLittleEndian = _CryptoNfcServices.intToLittleEndianHex(sectorNumber * 4);
    
    // MAC on command is always enabled for security
    final cmacResult = _calculateCmac(encryptedMacKey, transactionIdentifierHex, sectorNumber, commandCode);
    final readCommand = "$commandCode${sectorAddressLittleEndian}03$cmacResult";
    
    _debugPrint("📤 Read command (Code: $commandCode): $readCommand");
    
    final readResponse = await _transceiveCommand(readCommand);
    _debugPrint("📥 Read response: $readResponse");
    
    final errorCheck = _checkTransceiveError(readResponse, 'read block operation');
    if (errorCheck != null) {
      throw PlusException(errorCheck);
    }

    Uint8List decryptedData;
    if (isPlaintext) {
      // For plaintext communication, data is not encrypted
      decryptedData = Uint8List.fromList(hex.decode(readResponse.substring(2).substring(0, 96)));
    } else {
      // For encrypted communication, decrypt the data
      decryptedData = _crypto.aesDecrypt(
        Uint8List.fromList(hex.decode(readResponse.substring(2).substring(0, 96))),
        encryptedEncryptionKey,
        ivBytes: Uint8List.fromList(hex.decode("010000000100000001000000$transactionIdentifierHex")),
      );
    }
    
    final blockData = hex.encode(decryptedData).substring(
      blockNumber * 32, 
      blockNumber * 32 + 32,
    );
    
    _debugPrint("✅ Block data read successfully");
    return blockData;
  }

  /// Determines the appropriate read command code based on plaintext and MAC response requirements.
  /// MAC on command is always enabled for security (only supports 31h, 32h, 33h).
  /// 
  /// Based on the MIFARE Plus command table (restricted subset):
  /// - 31h: MAC on command=Yes, Plaintext=No, MAC on response=Yes
  /// - 32h: MAC on command=Yes, Plaintext=Yes, MAC on response=No
  /// - 33h: MAC on command=Yes, Plaintext=Yes, MAC on response=Yes
  String _getReadCommandCode({
    required bool isPlaintext,
    required bool requiresMacOnResponse,
  }) {
    // MAC on command is always enabled for security
    if (isPlaintext) {
      return requiresMacOnResponse ? "33" : "32";
    } else {
      return requiresMacOnResponse ? "31" : "31"; // Always use 31h for encrypted
    }
  }

  // =============================================================================
  // UTILITY METHODS
  // =============================================================================

  /// Safely executes an NFC transceive command with timeout.
  Future<String> _transceiveCommand(String command) async {
    try {
      return await FlutterNfcKit.transceive(command)
          .timeout(const Duration(seconds: 5));
    } on TimeoutException {
      throw const NfcException("Card communication timeout");
    } catch (e) {
      throw NfcException("Card communication failed", originalError: e);
    }
  }

  /// Validates input parameters for the main read operation.
  void _validateReadPlusParameters(
    String sector,
    String block,
    String keyType,
    String keyHex,
  ) {
    final params = {
      'sector': sector,
      'block': block,
      'keyType': keyType,
      'keyHex': keyHex,
    };
    
    for (final entry in params.entries) {
      if (entry.value.isEmpty) {
        throw ArgumentError("${entry.key} cannot be empty");
      }
    }
    
    _validateSectorNumber(sector);
    _validateBlockNumber(block);
    _validateKeyType(keyType);
    _validateHexString(keyHex, 'Authentication key', expectedLength: 32);
  }

  /// Validates sector number parameter.
  void _validateSectorNumber(String sectorString) {
    final sectorNumber = int.tryParse(sectorString);
    if (sectorNumber == null || sectorNumber < 0) {
      throw ArgumentError('Sector must be a non-negative integer, got: $sectorString');
    }
  }

  /// Validates block number parameter.
  void _validateBlockNumber(String blockString) {
    final blockNumber = int.tryParse(blockString);
    if (blockNumber == null || blockNumber < 0) {
      throw ArgumentError('Block must be a non-negative integer, got: $blockString');
    }
  }

  /// Validates key type parameter.
  void _validateKeyType(String keyType) {
    if (keyType != 'Key A' && keyType != 'Key B') {
      throw ArgumentError('KeyType must be "Key A" or "Key B", got: $keyType');
    }
  }

  /// Validates a hexadecimal string parameter.
  void _validateHexString(String hexString, String parameterName, {int? expectedLength}) {
    if (!_CryptoNfcServices._isValidHex(hexString)) {
      throw ArgumentError('$parameterName must contain only hexadecimal characters');
    }
    
    if (expectedLength != null && hexString.length != expectedLength) {
      throw ArgumentError(
        '$parameterName must be exactly $expectedLength characters long, got: ${hexString.length}',
      );
    }
  }

  /// Builds the authentication command for the specified sector and key type.
  String _buildAuthenticateCmd(int sectorNumber, String keyType) {
    final keySectorNumber = sectorNumber * 2 + (keyType == "Key A" ? 0 : 1);
    final keyNumberToSend = keySectorNumber.toRadixString(16).padLeft(2, '0').toUpperCase();
    return "70${keyNumberToSend}4000";
  }

  /// Decrypts RandomB from the authentication response.
  Uint8List _decryptRandomB(String encryptedRandomBHex, Uint8List authenticationKey, Uint8List initializationVector) {
    if (encryptedRandomBHex.length != _expectedEncryptedRndBLength) {
      throw PlusException('Unexpected encrypted RND B length: ${encryptedRandomBHex.length}');
    }
    final encryptedRandomB = Uint8List.fromList(hex.decode(encryptedRandomBHex));
    return _crypto.aesDecrypt(encryptedRandomB, authenticationKey, ivBytes: initializationVector);
  }

  /// Generates session keys from RandomA and RandomB.
  Map<String, Uint8List> _generateSessionKeys(Uint8List plainRandomA, Uint8List plainRandomB) {
    final encryptionKeyPartA = plainRandomA.sublist(11, 16);
    final encryptionKeyPartB = plainRandomB.sublist(11, 16);
    final encryptionKeyPartC = plainRandomA.sublist(4, 9);
    final encryptionKeyPartD = plainRandomB.sublist(4, 9);
    final encryptionKeyPartE = Uint8List.fromList(List.generate(5, (i) => encryptionKeyPartC[i] ^ encryptionKeyPartD[i]));
    final encryptionKey = Uint8List.fromList([...encryptionKeyPartA, ...encryptionKeyPartB, ...encryptionKeyPartE, 0x11]);
    
    final macKeyPartA = plainRandomA.sublist(7, 12);
    final macKeyPartB = plainRandomB.sublist(7, 12);
    final macKeyPartC = plainRandomA.sublist(0, 5);
    final macKeyPartD = plainRandomB.sublist(0, 5);
    final macKeyPartE = Uint8List.fromList(List.generate(5, (i) => macKeyPartC[i] ^ macKeyPartD[i]));
    final macKey = Uint8List.fromList([...macKeyPartA, ...macKeyPartB, ...macKeyPartE, 0x22]);
    
    return {'Kenc': encryptionKey, 'Kmac': macKey};
  }

  /// Calculates CMAC for command authentication.
  String _calculateCmac(Uint8List encryptedMacKey, String transactionIdentifierHex, int sectorNumber, String command) {
    final sectorAddressLittleEndian = _CryptoNfcServices.intToLittleEndianHex(sectorNumber * 4);
    final commandForMac = "${command}0000$transactionIdentifierHex${sectorAddressLittleEndian}03";
    final macOnCommand = _CryptoNfcServices.computeAesCmac(
      hex.encode(encryptedMacKey),
      commandForMac,
      128,
    );
    
    final regExp = RegExp(r'(?:..)(..)');
    final matches = regExp.allMatches(macOnCommand);
    return matches.map((m) => m.group(1)!).join();
  }

  /// Validates and handles MIFARE Plus error codes from transceive responses.
  /// 
  /// [response] The response from FlutterNfcKit.transceive
  /// [operation] Description of the operation for error context
  /// 
  /// Returns null if successful, or error message string if an error code is detected
  String? _checkTransceiveError(String response, String operation) {
    if (response.length < 2) {
      return 'Invalid response length from $operation';
    }
    
    // Check if response starts with '90' (success) or extract status code from end
    String statusCode;
    if (response.startsWith('90')) {
      statusCode = '90';
    } else {
      statusCode = response.substring(response.length - 2).toUpperCase();
    }
    
    switch (statusCode) {
      case '90':
        // Success - no error
        return null;
      case '00':
        return 'Success';
      case '06':
        return 'Authentication error - Authentication failed';
      case '07':
        return 'Command overflow - Too many read or write commands in the session or transaction';
      case '08':
        return 'Invalid MAC - Invalid MAC in command or response';
      case '09':
        return 'Invalid block number - Block number is not valid';
      case '0A':
        return 'Block does not exist - Invalid block number, not existing block number';
      case '0B':
        return 'Conditions of use not satisfied - The current command code not available at current card state';
      case '0C':
        return 'Length error - Length error';
      case '0E':
        return 'Out of EEPROM - Insufficient EEPROM memory';
      case '0F':
        return 'General manipulation error - Failure in the operation of the PICC or increment/decrement overflow/underflow';
      case '1C':
        return 'Illegal command - Command not supported';
      case '1E':
        return 'Integrity error - Data integrity error';
      case '40':
        return 'No such key - Authentication key not found';
      case '6E':
        return 'Error (ISO) - ISO 14443 error';
      case '7E':
        return 'Length error in command - Length of command string invalid';
      case '9D':
        return 'Permission denied - Current configuration/status does not allow the requested command';
      case '9E':
        return 'Parameter error - Value of the parameter(s) invalid';
      case 'A0':
        return 'Application not found - Requested AID not present on PICC';
      case 'A1':
        return 'Application integrity error - Unrecoverable error within application';
      case 'AE':
        return 'Authentication error - Current authentication status does not allow the requested command';
      case 'AF':
        return 'Additional frame expected - Additional data frame is expected to be sent';
      case 'BE':
        return 'Boundary error - Attempt to read/write data from/to beyond the file\'s/record\'s limits';
      case 'C1':
        return 'PICC integrity error - Unrecoverable error within PICC';
      case 'CA':
        return 'Command aborted - Previous command was not fully completed';
      case 'CD':
        return 'PICC disabled - PICC was disabled by an unrecoverable error';
      case 'CE':
        return 'Count error - Number of applications limited to 28';
      case 'DE':
        return 'Duplicate error - Creation of file/application failed because file/application already exists';
      case 'EE':
        return 'EEPROM error - Could not complete NV-write operation due to loss of power';
      case 'F0':
        return 'File not found - Specified file number does not exist';
      case 'F1':
        return 'File integrity error - Unrecoverable error within file';
      default:
        // For other error codes or unexpected responses
        if (!response.startsWith('90')) {
          return 'Unknown error code during $operation - Unexpected response: $response';
        }
        return null;
    }
  }

  /// Converts NFC error codes to descriptive error messages.
  String _getNfcErrorMessage(String errorCode) {
    switch (errorCode) {
      case "00":
        return "NFC is available and enabled";
      case "E1":
        return "NFC is available but disabled by user";
      case "E2":
        return "NFC is not supported on this device";
      case "E3":
        return "Unknown NFC availability status";
      case "E4":
        return "Platform error occurred";
      case "E5":
        return "Unexpected error occurred";
      default:
        return "Unknown error code: $errorCode";
    }
  }

  /// Safely finishes the NFC session.
  Future<void> _finishNfcSession() async {
    try {
      await FlutterNfcKit.finish(iosAlertMessage: "Scan completed");
      _debugPrint("📱 NFC session finished");
    } catch (e) {
      _debugPrint("⚠️ Error finishing NFC session: $e");
    }
  }

  /// Prints debug messages only when debug mode is enabled.
  void _debugPrint(String message) {
    if (debugMode) {
      print('[${DateTime.now().toIso8601String()}] Plus: $message');
    }
  }
}

// =============================================================================
// BINARY CONVERSION SERVICES
// =============================================================================

/// Production-ready binary conversion utilities for data processing.
/// 
/// Provides various conversion methods for binary data formats with
/// comprehensive input validation and error handling.
/// 
/// Features:
/// - Hex to binary conversion with formatting
/// - Binary to hex conversion
/// - Hex to ASCII conversion
/// - Byte range extraction with optional reversal
/// - Input validation and sanitization
class BinaryConversionServices {
  final bool debugMode;

  /// Creates a new instance of BinaryConversionServices.
  /// 
  /// [debugMode] If true, enables debug logging.
  BinaryConversionServices({this.debugMode = false});

  /// Converts hex string to formatted binary string with byte range extraction.
  /// 
  /// [hexString] The hex string to convert (must be valid hex)
  /// [firstBytePosition] First byte position (0-based index)
  /// [lastBytePosition] Last byte position (0-based index)
  /// 
  /// Returns binary string for the specified byte range with line breaks every 8 bits.
  /// If firstBytePosition > lastBytePosition, bytes are processed in reverse order.
  /// 
  /// Throws [ArgumentError] if parameters are invalid.
  String toFormatedBINString(String hexString, int firstBytePosition, int lastBytePosition) {
    _validateHexString(hexString);
    _validateBytePositions(hexString, firstBytePosition, lastBytePosition);
    
    final binaryLines = <String>[];
    final (startPosition, endPosition, isReversed) = _calculateRange(firstBytePosition, lastBytePosition);
    
    if (isReversed) {
      for (int i = startPosition; i >= endPosition; i--) {
        final byteValue = _hexByteAt(hexString, i);
        final binaryString = byteValue.toRadixString(2).padLeft(8, '0');
        binaryLines.add(binaryString);
      }
    } else {
      for (int i = startPosition; i <= endPosition; i++) {
        final byteValue = _hexByteAt(hexString, i);
        final binaryString = byteValue.toRadixString(2).padLeft(8, '0');
        binaryLines.add(binaryString);
      }
    }
    
    return binaryLines.join('\n');
  }
  /// Converts binary string to hex string with byte range extraction.
  /// 
  /// [binaryString] The binary string to convert (must contain only 0s and 1s)
  /// [firstBytePosition] First byte position (0-based index)
  /// [lastBytePosition] Last byte position (0-based index)
  /// 
  /// Returns hex string for the specified byte range.
  /// If firstBytePosition > lastBytePosition, bytes are processed in reverse order.
  /// 
  /// Throws [ArgumentError] if parameters are invalid.
  String toHexFromBINString(String binaryString, int firstBytePosition, int lastBytePosition) {
    _validateBinaryString(binaryString);
    _validateBinaryBytePositions(binaryString, firstBytePosition, lastBytePosition);
    
    final hexStringBuffer = StringBuffer();
    final (startPosition, endPosition, isReversed) = _calculateRange(firstBytePosition, lastBytePosition);
    
    if (isReversed) {
      for (int i = startPosition; i >= endPosition; i--) {
        final byteStart = i * 8;
        final byteEnd = byteStart + 8;
        final byteBinary = binaryString.substring(byteStart, byteEnd);
        final byteValue = int.parse(byteBinary, radix: 2);
        final hexByte = byteValue.toRadixString(16).padLeft(2, '0');
        hexStringBuffer.write(hexByte);
      }
    } else {
      for (int i = startPosition; i <= endPosition; i++) {
        final byteStart = i * 8;
        final byteEnd = byteStart + 8;
        final byteBinary = binaryString.substring(byteStart, byteEnd);
        final byteValue = int.parse(byteBinary, radix: 2);
        final hexByte = byteValue.toRadixString(16).padLeft(2, '0');
        hexStringBuffer.write(hexByte);
      }
    }
    
    return hexStringBuffer.toString().toUpperCase();
  }
  /// Converts hex string to ASCII string with byte range extraction.
  /// 
  /// [hexString] The hex string to convert (must be valid hex)
  /// [firstBytePosition] First byte position (0-based index)
  /// [lastBytePosition] Last byte position (0-based index)
  /// 
  /// Returns ASCII string for the specified byte range.
  /// If firstBytePosition > lastBytePosition, bytes are processed in reverse order.
  /// Non-printable characters (outside 32-126 range) are replaced with '.'.
  /// 
  /// Throws [ArgumentError] if parameters are invalid.
  String toASCIIString(String hexString, int firstBytePosition, int lastBytePosition) {
    _validateHexString(hexString);
    _validateBytePositions(hexString, firstBytePosition, lastBytePosition);
    
    final asciiStringBuffer = StringBuffer();
    final (startPosition, endPosition, isReversed) = _calculateRange(firstBytePosition, lastBytePosition);
    
    if (isReversed) {
      for (int i = startPosition; i >= endPosition; i--) {
        final byteValue = _hexByteAt(hexString, i);
        final asciiChar = _byteToAsciiChar(byteValue);
        asciiStringBuffer.write(asciiChar);
      }
    } else {
      for (int i = startPosition; i <= endPosition; i++) {
        final byteValue = _hexByteAt(hexString, i);
        final asciiChar = _byteToAsciiChar(byteValue);
        asciiStringBuffer.write(asciiChar);
      }
    }
    
    return asciiStringBuffer.toString();
  }

  /// Converts hex string to formatted hex string with spaces and byte range extraction.
  /// 
  /// [hexString] The hex string to convert (must be valid hex)
  /// [firstBytePosition] First byte position (0-based index)
  /// [lastBytePosition] Last byte position (0-based index)
  /// 
  /// Returns formatted hex string with spaces between bytes for the specified byte range.
  /// If firstBytePosition > lastBytePosition, bytes are processed in reverse order.
  /// 
  /// Throws [ArgumentError] if parameters are invalid.
  String toFormatedHEXString(String hexString, int firstBytePosition, int lastBytePosition) {
    _validateHexString(hexString);
    _validateBytePositions(hexString, firstBytePosition, lastBytePosition);
    
    final hexPairs = <String>[];
    final (startPosition, endPosition, isReversed) = _calculateRange(firstBytePosition, lastBytePosition);
    
    if (isReversed) {
      for (int i = startPosition; i >= endPosition; i--) {
        final byteHex = hexString.substring(i * 2, (i * 2) + 2).toUpperCase();
        hexPairs.add(byteHex);
      }
    } else {
      for (int i = startPosition; i <= endPosition; i++) {
        final byteHex = hexString.substring(i * 2, (i * 2) + 2).toUpperCase();
        hexPairs.add(byteHex);
      }
    }
    
    return hexPairs.join(' ');
  }

  // =============================================================================
  // PRIVATE UTILITY METHODS
  // =============================================================================

  /// Validates hex string format and content.
  void _validateHexString(String hexString) {
    ArgumentError.checkNotNull(hexString, 'hexString');
    
    if (hexString.isEmpty) {
      throw ArgumentError('Hex string cannot be empty');
    }
    if (hexString.length % 2 != 0) {
      throw ArgumentError('Hex string length must be even, got: ${hexString.length}');
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(hexString)) {
      throw ArgumentError('Hex string must contain only hexadecimal characters');
    }
  }

  /// Validates binary string format and content.
  void _validateBinaryString(String binaryString) {
    ArgumentError.checkNotNull(binaryString, 'binaryString');
    
    if (binaryString.isEmpty) {
      throw ArgumentError('Binary string cannot be empty');
    }
    if (binaryString.length % 8 != 0) {
      throw ArgumentError('Binary string length must be multiple of 8, got: ${binaryString.length}');
    }
    if (!RegExp(r'^[01]+$').hasMatch(binaryString)) {
      throw ArgumentError('Binary string contains invalid characters. Only 0 and 1 are allowed');
    }
  }
  /// Validates byte positions for hex string operations.
  void _validateBytePositions(String hexString, int firstBytePosition, int lastBytePosition) {
    if (firstBytePosition < 0 || lastBytePosition < 0) {
      throw ArgumentError('Byte positions must be non-negative, got firstBytePosition: $firstBytePosition, lastBytePosition: $lastBytePosition');
    }
    
    final totalBytes = hexString.length ~/ 2;
    final maxIndex = totalBytes - 1;
    
    if (firstBytePosition > maxIndex || lastBytePosition > maxIndex) {
      throw ArgumentError(
        'Byte positions exceed available bytes (max: $maxIndex), got firstBytePosition: $firstBytePosition, lastBytePosition: $lastBytePosition (Total bytes: $totalBytes)'
      );
    }
  }

  /// Validates byte positions for binary string operations.
  void _validateBinaryBytePositions(String binaryString, int firstBytePosition, int lastBytePosition) {
    if (firstBytePosition < 0 || lastBytePosition < 0) {
      throw ArgumentError('Byte positions must be non-negative. First: $firstBytePosition, Last: $lastBytePosition');
    }
    
    final totalBytes = binaryString.length ~/ 8;
    final maxIndex = totalBytes - 1;
    
    if (firstBytePosition > maxIndex || lastBytePosition > maxIndex) {
      throw ArgumentError(
        'Byte positions out of range. First: $firstBytePosition, Last: $lastBytePosition, Max index: $maxIndex (Total bytes: $totalBytes)'
      );
    }
  }

  /// Calculates processing range and determines if reversal is needed.
  (int startPosition, int endPosition, bool isReversed) _calculateRange(int firstBytePosition, int lastBytePosition) {
    if (firstBytePosition > lastBytePosition) {
      return (firstBytePosition, lastBytePosition, true);
    } else {
      return (firstBytePosition, lastBytePosition, false);
    }
  }
  /// Extracts a byte value from hex string at specified position.
  int _hexByteAt(String hexString, int byteIndex) {
    final byteHex = hexString.substring(byteIndex * 2, (byteIndex * 2) + 2);
    return int.parse(byteHex, radix: 16);
  }
  /// Converts byte value to ASCII character or '.' for non-printable.
  String _byteToAsciiChar(int byte) {
    return (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
  }
}