# NFC SERVICES LIBRARY
## USER MANUAL & API REFERENCE

**Version:** 1.0.0  
**Package Name:** roger_nfc_services  
**Author:** NFC Development Team  
**Date:** January 2025  
**Flutter SDK:** ^3.7.2  

---

## TABLE OF CONTENTS

1. [INTRODUCTION](#1-introduction)
2. [LIBRARY ARCHITECTURE](#2-library-architecture)
3. [NFC SERVICE CLASSES](#3-nfc-service-classes)
4. [API METHODS & CONFIGURATION](#4-api-methods--configuration)
5. [USAGE EXAMPLES & IMPLEMENTATION](#5-usage-examples--implementation)
6. [ERROR HANDLING & TROUBLESHOOTING](#6-error-handling--troubleshooting)
7. [PLATFORM CONSIDERATIONS](#7-platform-considerations)
8. [APPENDICES](#8-appendices)

---

## 1. INTRODUCTION

### 1.1 Overview

The NFC Services Library is a comprehensive Flutter/Dart package designed for Near Field Communication (NFC) operations with MIFARE Plus and DESFire cards. This library provides secure, authenticated access to NFC card data using AES-128 encryption and industry-standard authentication protocols.

### 1.2 Purpose and Target Applications

This library is designed for applications requiring:
- Secure NFC card reading with authentication
- MIFARE Plus sector and block data access
- DESFire application and file management
- Cryptographic operations for NFC security
- Cross-platform NFC functionality (Android/iOS)

### 1.3 Supported NFC Standards

| Standard | Card Type | Authentication | Data Access |
|----------|-----------|----------------|-------------|
| ISO 14443 Type A | MIFARE Plus | AES-128 | Sectors 1-39, Blocks 0-14 |
| ISO 14443 Type A | DESFire | AES-128 | Applications & Files |
| ISO 7816 | Generic | Platform-dependent | Limited |

### 1.4 Flutter/Dart Compatibility

- **Flutter SDK:** ^3.7.2 or higher
- **Dart SDK:** Compatible with Flutter SDK requirements
- **Platform Support:** Android 5.0+, iOS 11.0+
- **Dependencies:** See [Dependencies](#dependencies) section

### 1.5 Key Features and Capabilities

- **Secure Authentication:** AES-128 encryption for all card communications
- **Multi-Card Support:** MIFARE Plus and DESFire card types
- **Error Handling:** Comprehensive error codes and recovery mechanisms
- **Debug Support:** Detailed logging for development and troubleshooting
- **Session Management:** Automatic NFC session handling and cleanup
- **Data Conversion:** Built-in utilities for binary, hex, ASCII, and decimal conversion

---

## 2. LIBRARY ARCHITECTURE

### 2.1 Package Structure

```
lib/nfc_services/
├── desfire_services.dart      # DESFire card operations
├── plus_services.dart         # MIFARE Plus card operations
└── shared/
    ├── nfc_utilities.dart     # Core NFC functionality
    ├── crypto_utilities.dart  # Cryptographic operations
    └── binary_conversion.dart # Data format conversion
```

### 2.2 Core Components

#### 2.2.1 Service Classes

| Class | Purpose | Primary Methods |
|-------|---------|-----------------|
| `DesfireNfcServices` | DESFire card operations | `readDesfire()` |
| `PlusServices` | MIFARE Plus operations | `readPlus()` |
| `NfcUtilities` | Base NFC functionality | `isNfcAvailable()`, `pollForCard()` |
| `CryptoUtilities` | Cryptographic operations | `aesEncrypt()`, `aesDecrypt()` |
| `BinaryConversion` | Data format conversion | `toBinary()`, `toHex()`, `toASCII()` |

#### 2.2.2 Result Types

The library uses sealed classes for type-safe result handling:

```dart
// DESFire Results
sealed class DesfireResult<T>
class DesfireSuccess<T> extends DesfireResult<T>
class DesfireError<T> extends DesfireResult<T>

// MIFARE Plus Results  
sealed class PlusResult<T>
class PlusSuccess<T> extends PlusResult<T>
class PlusError<T> extends PlusResult<T>

// NFC Utilities Results
class NfcResult
```

### 2.3 Data Flow Architecture

```
User Application
       ↓
Service Layer (DesfireNfcServices / PlusServices)
       ↓
NFC Utilities (Card Detection & Communication)
       ↓
Crypto Utilities (Authentication & Encryption)
       ↓
NFC Hardware (Card Communication)
```

---

## 3. NFC SERVICE CLASSES

### 3.1 DesfireNfcServices Class

#### 3.1.1 Class Overview

The `DesfireNfcServices` class provides comprehensive support for DESFire card operations including application selection, authentication, and encrypted file reading.

```dart
class DesfireNfcServices {
  final bool debugMode;
  final int timeout;
  final String alertMessage;
  final String multipleTagMessage;
}
```

#### 3.1.2 Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `debugMode` | `bool` | `false` | Enables detailed operation logging |
| `timeout` | `int` | `7` | NFC operation timeout in seconds |
| `alertMessage` | `String` | `"Scan your DESFire card"` | User prompt message |
| `multipleTagMessage` | `String` | `"Multiple tags found!"` | Multiple tag detection message |

#### 3.1.3 Key Methods

| Method | Return Type | Description |
|--------|-------------|-------------|
| `readDesfire()` | `Future<DesfireResult<String>>` | Main method for reading DESFire card data |

### 3.2 PlusServices Class

#### 3.2.1 Class Overview

The `PlusServices` class handles MIFARE Plus card operations including sector authentication and block data reading with AES encryption.

```dart
class PlusServices {
  final bool debugMode;
  final int timeout;
  final String alertMessage;
  final String multipleTagMessage;
}
```

#### 3.2.2 Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `debugMode` | `bool` | `false` | Enables detailed operation logging |
| `timeout` | `int` | `10` | NFC operation timeout in seconds |
| `alertMessage` | `String` | `"Scan your MIFARE Plus card"` | User prompt message |
| `multipleTagMessage` | `String` | `"Multiple tags found!"` | Multiple tag detection message |

#### 3.2.3 Key Methods

| Method | Return Type | Description |
|--------|-------------|-------------|
| `readPlus()` | `Future<PlusResult<String>>` | Main method for reading MIFARE Plus card data |

### 3.3 Shared Utility Classes

#### 3.3.1 NfcUtilities

Core NFC functionality shared across all card types.

**Key Functions:**
- `isNfcAvailable()` - Check NFC hardware availability
- `pollForCard()` - Detect and validate NFC cards
- `sendCommand()` - Send single command to card
- `sendCommands()` - Send multiple commands sequentially

#### 3.3.2 CryptoUtilities

Cryptographic operations for secure NFC communications.

**Key Functions:**
- `aesEncrypt()` - AES-CBC encryption
- `aesDecrypt()` - AES-CBC decryption
- `generateSecureRandom()` - Cryptographically secure random generation
- `computeAesCmac()` - AES-CMAC computation

#### 3.3.3 BinaryConversion

Data format conversion utilities.

**Key Functions:**
- `toBinary()` - Convert hex to binary representation
- `toHex()` - Convert to spaced hex format
- `toASCII()` - Convert to ASCII string
- `toDecimal()` - Convert to decimal representation

---

## 4. API METHODS & CONFIGURATION

### 4.1 DESFire API Reference

#### 4.1.1 readDesfire Method

```dart
Future<DesfireResult<String>> readDesfire({
  required String applicationId,
  required String fileId,
  required String keyNumber,
  required String authKey,
})
```

**Parameters:**

| Parameter | Type | Format | Description |
|-----------|------|--------|-------------|
| `applicationId` | `String` | 6 hex chars | DESFire application ID (e.g., "123456") |
| `fileId` | `String` | 2 hex chars | File ID within application (e.g., "01") |
| `keyNumber` | `String` | 2 hex chars | Authentication key number (e.g., "00") |
| `authKey` | `String` | 32 hex chars | AES-128 authentication key |

**Return Value:**
- `DesfireSuccess<String>` - Contains decrypted file data as hex string
- `DesfireError<String>` - Contains error code and description

**Example:**
```dart
final desfireService = DesfireNfcServices(debugMode: true);
final result = await desfireService.readDesfire(
  applicationId: "123456",
  fileId: "01", 
  keyNumber: "00",
  authKey: "00112233445566778899AABBCCDDEEFF",
);

if (result.isSuccess) {
  print("Data: ${result.data}");
} else {
  print("Error: ${result.errorCode?.description}");
}
```

#### 4.1.2 DESFire Error Codes

| Code | Description | Resolution |
|------|-------------|------------|
| `DAID` | Invalid application ID | Ensure 6 hex characters |
| `DFID` | Invalid file ID | Ensure 2 hex characters |
| `DKN` | Invalid key number | Ensure 2 hex characters |
| `DAK` | Invalid authentication key | Ensure 32 hex characters |
| `DAF` | Authentication failed | Verify key and permissions |
| `DANF` | Application not found | Check application exists on card |
| `DFNF` | File not found | Check file exists in application |

### 4.2 MIFARE Plus API Reference

#### 4.2.1 readPlus Method

```dart
Future<PlusResult<String>> readPlus({
  required int sector,
  required int block,
  required KeyType keyType,
  required String keyHex,
})
```

**Parameters:**

| Parameter | Type | Range/Format | Description |
|-----------|------|--------------|-------------|
| `sector` | `int` | 1-39 | MIFARE Plus sector number |
| `block` | `int` | 0-14 | Block number within sector |
| `keyType` | `KeyType` | `KeyType.keyA` or `KeyType.keyB` | Authentication key type |
| `keyHex` | `String` | 32 hex chars | AES-128 authentication key |

**Return Value:**
- `PlusSuccess<String>` - Contains block data as hex string
- `PlusError<String>` - Contains error code and description

**Example:**
```dart
final plusService = PlusServices(debugMode: true);
final result = await plusService.readPlus(
  sector: 1,
  block: 0,
  keyType: KeyType.keyA,
  keyHex: "00112233445566778899AABBCCDDEEFF",
);

if (result.isSuccess) {
  print("Block data: ${result.data}");
} else {
  print("Error: ${result.errorCode?.description}");
}
```

#### 4.2.2 MIFARE Plus Error Codes

| Code | Description | Resolution |
|------|-------------|------------|
| `PPS` | Invalid sector number | Use sectors 1-39 |
| `PPB` | Invalid block number | Use blocks 0-14 |
| `PPKT` | Invalid key type | Use KeyType.keyA or KeyType.keyB |
| `PPK` | Invalid key hex format | Ensure 32 hex characters |
| `PPAF` | Authentication failed | Verify key and permissions |
| `PCCL` | Card connection lost | Keep card steady during operation |

### 4.3 NFC Utilities API Reference

#### 4.3.1 isNfcAvailable Function

```dart
Future<NfcResult> isNfcAvailable()
```

**Return Value:**
- `NfcResult` with success/error status and message

**Usage:**
```dart
final nfcStatus = await isNfcAvailable();
if (nfcStatus.isSuccess) {
  // NFC is available
} else {
  print("NFC Error: ${nfcStatus.message}");
}
```

#### 4.3.2 pollForCard Function

```dart
Future<NfcResult> pollForCard(
  bool debugMode, 
  int timeout, 
  String alertMessage, 
  String multipleTagMessage
)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `debugMode` | `bool` | Enable debug logging |
| `timeout` | `int` | Timeout in seconds |
| `alertMessage` | `String` | User prompt message |
| `multipleTagMessage` | `String` | Multiple tag message |

---

## 5. USAGE EXAMPLES & IMPLEMENTATION

### 5.1 Basic DESFire Implementation

```dart
import 'package:flutter/material.dart';
import 'package:roger_nfc_services/nfc_services/desfire_services.dart';

class DesfireExample extends StatefulWidget {
  @override
  _DesfireExampleState createState() => _DesfireExampleState();
}

class _DesfireExampleState extends State<DesfireExample> {
  final _desfireService = DesfireNfcServices(debugMode: true);
  String _result = '';
  bool _isReading = false;

  Future<void> _readDesfireCard() async {
    setState(() {
      _isReading = true;
      _result = 'Reading card...';
    });

    try {
      final result = await _desfireService.readDesfire(
        applicationId: "123456",
        fileId: "01",
        keyNumber: "00", 
        authKey: "00112233445566778899AABBCCDDEEFF",
      );

      setState(() {
        if (result.isSuccess) {
          _result = 'Success: ${result.data}';
        } else {
          _result = 'Error: ${result.errorCode?.description}';
        }
      });
    } catch (e) {
      setState(() {
        _result = 'Exception: $e';
      });
    } finally {
      setState(() {
        _isReading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('DESFire Reader')),
      body: Padding(
        padding: EdgeInsets.all(16),
        child: Column(
          children: [
            ElevatedButton(
              onPressed: _isReading ? null : _readDesfireCard,
              child: Text(_isReading ? 'Reading...' : 'Read DESFire Card'),
            ),
            SizedBox(height: 20),
            Text(_result),
          ],
        ),
      ),
    );
  }
}
```

### 5.2 Basic MIFARE Plus Implementation

```dart
import 'package:flutter/material.dart';
import 'package:roger_nfc_services/nfc_services/plus_services.dart';

class PlusExample extends StatefulWidget {
  @override
  _PlusExampleState createState() => _PlusExampleState();
}

class _PlusExampleState extends State<PlusExample> {
  final _plusService = PlusServices(debugMode: true);
  String _result = '';
  bool _isReading = false;

  Future<void> _readPlusCard() async {
    setState(() {
      _isReading = true;
      _result = 'Reading card...';
    });

    try {
      final result = await _plusService.readPlus(
        sector: 1,
        block: 0,
        keyType: KeyType.keyA,
        keyHex: "00112233445566778899AABBCCDDEEFF",
      );

      setState(() {
        if (result.isSuccess) {
          _result = 'Success: ${result.data}';
        } else {
          _result = 'Error: ${result.errorCode?.description}';
        }
      });
    } catch (e) {
      setState(() {
        _result = 'Exception: $e';
      });
    } finally {
      setState(() {
        _isReading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('MIFARE Plus Reader')),
      body: Padding(
        padding: EdgeInsets.all(16),
        child: Column(
          children: [
            ElevatedButton(
              onPressed: _isReading ? null : _readPlusCard,
              child: Text(_isReading ? 'Reading...' : 'Read Plus Card'),
            ),
            SizedBox(height: 20),
            Text(_result),
          ],
        ),
      ),
    );
  }
}
```

### 5.3 Advanced Data Processing

```dart
import 'package:roger_nfc_services/nfc_services/shared/binary_conversion.dart';

class DataProcessor {
  static void processCardData(String hexData) {
    try {
      // Convert to different formats
      final binary = BinaryConversion.toBinary(hexData, 0, 3);
      final hex = BinaryConversion.toHex(hexData, 0, 3);
      final ascii = BinaryConversion.toASCII(hexData, 0, 3);
      final decimal = BinaryConversion.toDecimal(hexData, 0, 3);
      
      print('Original: $hexData');
      print('Binary: $binary');
      print('Hex: $hex');
      print('ASCII: $ascii');
      print('Decimal: $decimal');
      
      // Extract specific bytes
      final firstByte = BinaryConversion.getByte(hexData, 0);
      print('First byte: $firstByte');
      
    } catch (e) {
      print('Data processing error: $e');
    }
  }
}
```

### 5.4 NFC Availability Check

```dart
import 'package:roger_nfc_services/nfc_services/shared/nfc_utilities.dart';

class NfcChecker {
  static Future<bool> checkAndPromptNfc(BuildContext context) async {
    final nfcStatus = await isNfcAvailable();
    
    if (!nfcStatus.isSuccess) {
      showDialog(
        context: context,
        builder: (context) => AlertDialog(
          title: Text('NFC Error'),
          content: Text(nfcStatus.message ?? 'Unknown NFC error'),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: Text('OK'),
            ),
          ],
        ),
      );
      return false;
    }
    
    return true;
  }
}
```

---

## 6. ERROR HANDLING & TROUBLESHOOTING

### 6.1 Error Handling Strategy

The library implements a comprehensive error handling system using sealed classes and specific error codes for each operation type.

#### 6.1.1 Result Pattern Usage

```dart
// Always check result type before accessing data
final result = await service.readCard(...);

if (result.isSuccess) {
  // Safe to access result.data
  processData(result.data!);
} else {
  // Handle error with specific error code
  handleError(result.errorCode!);
}
```

#### 6.1.2 Error Recovery Patterns

```dart
Future<String?> readCardWithRetry(int maxRetries) async {
  for (int attempt = 1; attempt <= maxRetries; attempt++) {
    final result = await service.readCard(...);
    
    if (result.isSuccess) {
      return result.data;
    }
    
    // Retry for specific error types
    if (result.errorCode == ErrorCode.cardConnectionLost && 
        attempt < maxRetries) {
      await Future.delayed(Duration(milliseconds: 500));
      continue;
    }
    
    // Don't retry for authentication errors
    if (result.errorCode == ErrorCode.authenticationFailed) {
      break;
    }
  }
  
  return null;
}
```

### 6.2 Common Issues and Solutions

#### 6.2.1 Authentication Issues

**Problem:** Authentication failed errors  
**Symptoms:** `DAF` (DESFire) or `PPAF` (MIFARE Plus) error codes  
**Solutions:**
- Verify authentication key is correct (32 hex characters)
- Check key number/type matches card configuration
- Ensure card has not been locked due to failed attempts
- Verify application/sector exists and is accessible

**Example Fix:**
```dart
// Verify key format before authentication
bool isValidKey(String key) {
  return key.length == 32 && 
         RegExp(r'^[0-9A-Fa-f]+$').hasMatch(key);
}

if (!isValidKey(authKey)) {
  return Error('Invalid key format');
}
```

#### 6.2.2 Connection Issues

**Problem:** Card connection lost during operation  
**Symptoms:** `DCCL` or `PCCL` error codes  
**Solutions:**
- Instruct user to keep card steady
- Implement retry mechanism with delays
- Use shorter timeout values
- Check for interference from other NFC devices

**Example Fix:**
```dart
Future<Result> readWithStabilityCheck() async {
  // Multiple short attempts instead of one long one
  for (int i = 0; i < 3; i++) {
    try {
      final result = await service.readCard(...);
      if (result.isSuccess) return result;
      
      if (result.errorCode?.code.contains('CCL') == true) {
        await Future.delayed(Duration(milliseconds: 200));
        continue;
      }
      
      return result; // Other errors, don't retry
    } catch (e) {
      if (i == 2) rethrow; // Last attempt
      await Future.delayed(Duration(milliseconds: 200));
    }
  }
}
```

#### 6.2.3 Platform-Specific Issues

**Android:**
- **Permission Issues:** Ensure NFC permission in AndroidManifest.xml
- **Background Restrictions:** NFC operations may fail in background
- **Hardware Variations:** Some devices have weaker NFC antennas

**iOS:**
- **Core NFC Limitations:** iOS has stricter NFC session management
- **Background Restrictions:** NFC only works in foreground
- **User Interaction Required:** iOS requires explicit user action

### 6.3 Debug Mode Usage

Enable debug mode for detailed operation logging:

```dart
final service = DesfireNfcServices(debugMode: true);
```

Debug output includes:
- Command/response hex data
- Authentication step details
- Timing information
- Error context

### 6.4 Performance Optimization

#### 6.4.1 Timeout Configuration

```dart
// Adjust timeouts based on use case
final quickService = PlusServices(timeout: 5);  // Fast operations
final reliableService = PlusServices(timeout: 15); // Reliable operations
```

#### 6.4.2 Batch Operations

```dart
// Read multiple blocks efficiently
Future<List<String>> readMultipleBlocks(
  List<int> blocks, 
  int sector, 
  KeyType keyType, 
  String keyHex
) async {
  final results = <String>[];
  
  // Authenticate once for the sector
  // Then read multiple blocks in the same session
  for (final block in blocks) {
    final result = await service.readPlus(
      sector: sector,
      block: block,
      keyType: keyType,
      keyHex: keyHex,
    );
    
    if (result.isSuccess) {
      results.add(result.data!);
    } else {
      throw Exception('Failed to read block $block: ${result.errorCode}');
    }
  }
  
  return results;
}
```

---

## 7. PLATFORM CONSIDERATIONS

### 7.1 Android Implementation

#### 7.1.1 Permissions and Manifest

Add to `android/app/src/main/AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.NFC" />
<uses-feature 
    android:name="android.hardware.nfc" 
    android:required="true" />

<activity
    android:name=".MainActivity"
    android:exported="true"
    android:launchMode="singleTop"
    android:theme="@style/LaunchTheme">
    
    <intent-filter android:autoVerify="true">
        <action android:name="android.nfc.action.TECH_DISCOVERED" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
    
    <meta-data 
        android:name="android.nfc.action.TECH_DISCOVERED"
        android:resource="@xml/nfc_tech_filter" />
</activity>
```

Create `android/app/src/main/res/xml/nfc_tech_filter.xml`:

```xml
<resources xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
    <tech-list>
        <tech>android.nfc.tech.IsoDep</tech>
    </tech-list>
    <tech-list>
        <tech>android.nfc.tech.MifareClassic</tech>
    </tech-list>
    <tech-list>
        <tech>android.nfc.tech.NfcA</tech>
    </tech-list>
</resources>
```

#### 7.1.2 Android-Specific Considerations

| Aspect | Details | Recommendations |
|--------|---------|-----------------|
| **Hardware Variations** | Different NFC antenna positions and strengths | Test on multiple devices |
| **Background Processing** | Limited NFC access in background | Perform operations in foreground |
| **Power Management** | Aggressive power saving may affect NFC | Request battery optimization exemption |
| **Security** | Android keystore integration possible | Consider secure key storage |

### 7.2 iOS Implementation

#### 7.2.1 Capabilities and Info.plist

Add to `ios/Runner/Info.plist`:

```xml
<key>NFCReaderUsageDescription</key>
<string>This app uses NFC to read MIFARE Plus and DESFire cards</string>

<key>com.apple.developer.nfc.readersession.formats</key>
<array>
    <string>NDEF</string>
    <string>TAG</string>
</array>

<key>com.apple.developer.nfc.readersession.iso7816.select-identifiers</key>
<array>
    <string>A0000000031010</string>
    <string>A0000000031011</string>
</array>
```

Add NFC capability in Xcode:
1. Select project target
2. Go to "Signing & Capabilities"
3. Add "Near Field Communication Tag Reading"

#### 7.2.2 iOS-Specific Considerations

| Aspect | Details | Recommendations |
|--------|---------|-----------------|
| **Session Management** | Strict 60-second session limit | Complete operations quickly |
| **User Interaction** | Requires explicit user action to start | Clear UI prompts |
| **Background Restrictions** | No background NFC operations | Design for foreground use |
| **Hardware Limitations** | NFC only on iPhone 7+ | Check device compatibility |

### 7.3 Cross-Platform Best Practices

#### 7.3.1 Platform Detection

```dart
import 'dart:io';

class PlatformUtils {
  static bool get isAndroid => Platform.isAndroid;
  static bool get isIOS => Platform.isIOS;
  
  static int get recommendedTimeout => isIOS ? 30 : 10;
  
  static String get platformSpecificMessage {
    if (isIOS) {
      return "Hold your iPhone near the card";
    } else {
      return "Place card on the back of your device";
    }
  }
}
```

#### 7.3.2 Adaptive UI Design

```dart
Widget buildNfcPrompt() {
  return Column(
    children: [
      Icon(
        Icons.nfc,
        size: 64,
        color: Theme.of(context).primaryColor,
      ),
      SizedBox(height: 16),
      Text(
        PlatformUtils.platformSpecificMessage,
        style: Theme.of(context).textTheme.titleMedium,
        textAlign: TextAlign.center,
      ),
      if (PlatformUtils.isIOS) ...[
        SizedBox(height: 8),
        Text(
          "Session will timeout in 60 seconds",
          style: Theme.of(context).textTheme.bodySmall,
        ),
      ],
    ],
  );
}
```

### 7.4 Testing Strategy

#### 7.4.1 Device Testing Matrix

| Platform | Minimum Version | Recommended Devices | Notes |
|----------|----------------|-------------------|--------|
| **Android** | API 21 (5.0) | Pixel, Samsung Galaxy | Test NFC antenna positions |
| **iOS** | iOS 11.0 | iPhone 7+, iPhone SE | Test Core NFC limitations |

#### 7.4.2 Card Testing

| Card Type | Test Scenarios | Expected Results |
|-----------|----------------|------------------|
| **MIFARE Plus** | Authentication, Block Reading | Successful data retrieval |
| **DESFire** | App Selection, File Reading | Encrypted data decryption |
| **Unsupported** | Detection Attempt | Graceful error handling |

---

## 8. APPENDICES

### 8.1 Complete Code Examples

#### 8.1.1 Full Application Example

```dart
import 'package:flutter/material.dart';
import 'package:roger_nfc_services/nfc_services/desfire_services.dart';
import 'package:roger_nfc_services/nfc_services/plus_services.dart';
import 'package:roger_nfc_services/nfc_services/shared/nfc_utilities.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'NFC Services Demo',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: NfcDemoScreen(),
    );
  }
}

class NfcDemoScreen extends StatefulWidget {
  @override
  _NfcDemoScreenState createState() => _NfcDemoScreenState();
}

class _NfcDemoScreenState extends State<NfcDemoScreen> {
  final _desfireService = DesfireNfcServices(debugMode: true);
  final _plusService = PlusServices(debugMode: true);
  
  String _status = 'Ready';
  bool _isOperating = false;

  @override
  void initState() {
    super.initState();
    _checkNfcAvailability();
  }

  Future<void> _checkNfcAvailability() async {
    final result = await isNfcAvailable();
    setState(() {
      _status = result.isSuccess ? 'NFC Available' : 'NFC Error: ${result.message}';
    });
  }

  Future<void> _readDesfireCard() async {
    setState(() {
      _isOperating = true;
      _status = 'Reading DESFire card...';
    });

    try {
      final result = await _desfireService.readDesfire(
        applicationId: "123456",
        fileId: "01",
        keyNumber: "00",
        authKey: "00112233445566778899AABBCCDDEEFF",
      );

      setState(() {
        _status = result.isSuccess 
          ? 'DESFire Success: ${result.data}'
          : 'DESFire Error: ${result.errorCode?.description}';
      });
    } catch (e) {
      setState(() {
        _status = 'Exception: $e';
      });
    } finally {
      setState(() {
        _isOperating = false;
      });
    }
  }

  Future<void> _readPlusCard() async {
    setState(() {
      _isOperating = true;
      _status = 'Reading MIFARE Plus card...';
    });

    try {
      final result = await _plusService.readPlus(
        sector: 1,
        block: 0,
        keyType: KeyType.keyA,
        keyHex: "00112233445566778899AABBCCDDEEFF",
      );

      setState(() {
        _status = result.isSuccess 
          ? 'Plus Success: ${result.data}'
          : 'Plus Error: ${result.errorCode?.description}';
      });
    } catch (e) {
      setState(() {
        _status = 'Exception: $e';
      });
    } finally {
      setState(() {
        _isOperating = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('NFC Services Demo'),
      ),
      body: Padding(
        padding: EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Card(
              child: Padding(
                padding: EdgeInsets.all(16),
                child: Column(
                  children: [
                    Icon(Icons.nfc, size: 48, color: Colors.blue),
                    SizedBox(height: 8),
                    Text(
                      'Status',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    SizedBox(height: 8),
                    Text(
                      _status,
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: _status.contains('Error') ? Colors.red : Colors.green,
                      ),
                    ),
                  ],
                ),
              ),
            ),
            SizedBox(height: 20),
            ElevatedButton(
              onPressed: _isOperating ? null : _readDesfireCard,
              child: Text('Read DESFire Card'),
            ),
            SizedBox(height: 12),
            ElevatedButton(
              onPressed: _isOperating ? null : _readPlusCard,
              child: Text('Read MIFARE Plus Card'),
            ),
            SizedBox(height: 20),
            if (_isOperating)
              Center(
                child: CircularProgressIndicator(),
              ),
          ],
        ),
      ),
    );
  }
}
```

### 8.2 Constants Reference

#### 8.2.1 DESFire Constants

```dart
class DesfireConstants {
  static const int timeout = 7;
  static const String successStatus = '9100';
  static const String additionalFrameStatus = '91AF';
  static const String nfcSuccessCode = '90';
  static const int aesKeySize = 16;
  static const int aesBlockSize = 16;
  static const int randomSize = 16;
  static const int keyHexLength = 32;
  static const int applicationIdLength = 6;
  static const int maxRetryAttempts = 1;
}
```

#### 8.2.2 MIFARE Plus Constants

```dart
class PlusConstants {
  static const int minSector = 1;
  static const int maxSector = 39;
  static const int minBlock = 0;
  static const int maxBlock = 14;
  static const int aesBlockSize = 16;
  static const int keyHexLength = 32;
  static const String successCode = "00";
  static const String nfcSuccessCode = "90";
  static const int maxRetryAttempts = 1;
  static const int transactionIdLength = 4;
  static const int randomDataLength = 16;
}
```

### 8.3 Dependencies

#### 8.3.1 Required Dependencies

Add to `pubspec.yaml`:

```yaml
dependencies:
  flutter:
    sdk: flutter
  flutter_nfc_kit: ^3.3.1
  convert: ^3.0.1
  encrypt: ^5.0.1
  pointycastle: ^3.9.1
  shared_preferences: ^2.2.2

dev_dependencies:
  flutter_test:
    sdk: flutter
  flutter_lints: ^5.0.0
  mockito: ^5.0.0
```

#### 8.3.2 Dependency Descriptions

| Package | Purpose | Version |
|---------|---------|---------|
| `flutter_nfc_kit` | Core NFC functionality | ^3.3.1 |
| `convert` | Hex/binary data conversion | ^3.0.1 |
| `encrypt` | AES encryption operations | ^5.0.1 |
| `pointycastle` | CMAC cryptographic functions | ^3.9.1 |
| `shared_preferences` | Configuration storage | ^2.2.2 |
| `mockito` | Unit testing mocks | ^5.0.0 |

### 8.4 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | January 2025 | Initial release with DESFire and MIFARE Plus support |
| 0.1.0 | December 2024 | Development version |

### 8.5 Migration Guide

#### 8.5.1 From Version 0.1.0 to 1.0.0

**Breaking Changes:**
- Result types changed from generic `Result<T>` to specific `DesfireResult<T>` and `PlusResult<T>`
- Error codes restructured for better categorization
- Method signatures updated for consistency

**Migration Steps:**

1. **Update Result Handling:**
```dart
// Old (0.1.0)
final result = await service.readCard();
if (result.success) { ... }

// New (1.0.0)
final result = await service.readDesfire();
if (result.isSuccess) { ... }
```

2. **Update Error Handling:**
```dart
// Old (0.1.0)
if (result.error == "AUTH_FAILED") { ... }

// New (1.0.0)
if (result.errorCode == DesfireErrorCode.authenticationFailed) { ... }
```

3. **Update Import Statements:**
```dart
// Old (0.1.0)
import 'package:roger_nfc_services/nfc_services.dart';

// New (1.0.0)
import 'package:roger_nfc_services/nfc_services/desfire_services.dart';
import 'package:roger_nfc_services/nfc_services/plus_services.dart';
```

### 8.6 Support and Contributing

#### 8.6.1 Getting Help

- **Documentation:** This manual and inline code documentation
- **Issues:** Report bugs and feature requests through project repository
- **Community:** Join discussions in project forums

#### 8.6.2 Contributing Guidelines

1. **Code Style:** Follow Dart/Flutter style guidelines
2. **Testing:** Include unit tests for new features
3. **Documentation:** Update this manual for API changes
4. **Compatibility:** Maintain backward compatibility when possible

#### 8.6.3 Development Setup

```bash
# Clone repository
git clone <repository-url>
cd nfc-services

# Install dependencies
flutter pub get

# Run tests
flutter test

# Run example app
cd example
flutter run
```

---

**End of Documentation**

*This manual provides comprehensive coverage of the NFC Services Library. For the most up-to-date information, please refer to the inline code documentation and project repository.*
