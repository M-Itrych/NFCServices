import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../nfc_services/desfire_services.dart';
import '../nfc_services/shared/binary_conversion.dart';

/// Custom text formatter to convert input to uppercase
class UpperCaseTextFormatter extends TextInputFormatter {
  @override
  TextEditingValue formatEditUpdate(
    TextEditingValue oldValue,
    TextEditingValue newValue,
  ) {
    return TextEditingValue(
      text: newValue.text.toUpperCase(),
      selection: newValue.selection,
    );
  }
}

class DesfireScreen extends StatefulWidget {
  const DesfireScreen({Key? key}) : super(key: key);

  @override
  State<DesfireScreen> createState() => _DesfireScreenState();
}

class _DesfireScreenState extends State<DesfireScreen> {
  final _formKey = GlobalKey<FormState>();
  final TextEditingController _fbpController = TextEditingController(text: '0');
  final TextEditingController _lbpController = TextEditingController(text: '15');
  final TextEditingController _applicationIdController = TextEditingController(text: 'F40001');
  final TextEditingController _fileIdController = TextEditingController(text: '1');
  final TextEditingController _keyNumberController = TextEditingController(text: '0');
  final TextEditingController _authKeyController = TextEditingController(text: '00000000000000000000000000000000');
  final TextEditingController _resultController = TextEditingController();
  final TextEditingController _decodedController = TextEditingController();
  String _selectedFormat = 'HEX'; // Default format selection
  final List<String> _formats = ['HEX', 'BIN', 'ASCII'];
  bool _isScanning = false;
  bool _isDecoding = false;

  @override
  void dispose() {
    _fbpController.dispose();
    _lbpController.dispose();
    _applicationIdController.dispose();
    _fileIdController.dispose();
    _keyNumberController.dispose();
    _authKeyController.dispose();
    _resultController.dispose();
    _decodedController.dispose();
    super.dispose();
  }

  /// Validate byte position input (0-15)
  String? _validateBytePosition(String? value, String fieldName) {
    if (value == null || value.isEmpty) {
      return '$fieldName is required';
    }
    final position = int.tryParse(value);
    if (position == null || position < 0 || position > 15) {
      return '$fieldName must be between 0-15';
    }
    return null;
  }

  /// Validate application ID (6 hex characters)
  String? _validateApplicationId(String? value) {
    if (value == null || value.isEmpty) {
      return 'Application ID is required';
    }
    if (value.length != 6) {
      return 'Application ID must be exactly 6 hex characters';
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(value)) {
      return 'Application ID must contain only hex characters (0-9, A-F)';
    }
    return null;
  }

  /// Validate file ID (hex characters)
  String? _validateFileId(String? value) {
    if (value == null || value.isEmpty) {
      return 'File ID is required';
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(value)) {
      return 'File ID must contain only hex characters (0-9, A-F)';
    }
    return null;
  }

  /// Validate key number (hex characters)
  String? _validateKeyNumber(String? value) {
    if (value == null || value.isEmpty) {
      return 'Key number is required';
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(value)) {
      return 'Key number must contain only hex characters (0-9, A-F)';
    }
    return null;
  }

  /// Validate authentication key (32 hex characters)
  String? _validateAuthKey(String? value) {
    if (value == null || value.isEmpty) {
      return 'Authentication key is required';
    }
    if (value.length != 32) {
      return 'Key must be exactly 32 hex characters';
    }
    if (!RegExp(r'^[0-9A-Fa-f]+$').hasMatch(value)) {
      return 'Key must contain only hex characters (0-9, A-F)';
    }
    return null;
  }

  /// Check if all form inputs are valid
  bool _isFormValid() {
    return _validateBytePosition(_fbpController.text, 'FBP') == null &&
           _validateBytePosition(_lbpController.text, 'LBP') == null &&
           _validateApplicationId(_applicationIdController.text) == null &&
           _validateFileId(_fileIdController.text) == null &&
           _validateKeyNumber(_keyNumberController.text) == null &&
           _validateAuthKey(_authKeyController.text) == null;
  }

  /// Show validation errors in a dialog
  void _showValidationErrors() {
    final errors = <String>[];
    
    final fbpError = _validateBytePosition(_fbpController.text, 'FBP');
    if (fbpError != null) errors.add(fbpError);
    
    final lbpError = _validateBytePosition(_lbpController.text, 'LBP');
    if (lbpError != null) errors.add(lbpError);
    
    final appIdError = _validateApplicationId(_applicationIdController.text);
    if (appIdError != null) errors.add(appIdError);
    
    final fileIdError = _validateFileId(_fileIdController.text);
    if (fileIdError != null) errors.add(fileIdError);
    
    final keyNumError = _validateKeyNumber(_keyNumberController.text);
    if (keyNumError != null) errors.add(keyNumError);
    
    final keyError = _validateAuthKey(_authKeyController.text);
    if (keyError != null) errors.add(keyError);

    if (errors.isNotEmpty) {
      showDialog(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Validation Errors'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: errors.map((error) => Padding(
              padding: const EdgeInsets.symmetric(vertical: 4),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Icon(Icons.error, color: Colors.red, size: 16),
                  const SizedBox(width: 8),
                  Expanded(child: Text(error)),
                ],
              ),
            )).toList(),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('OK'),
            ),
          ],
        ),
      );
    }
  }

  // Decode the raw output using the selected format
  Future<void> _decodeData() async {
    if (_resultController.text.isEmpty || _resultController.text.startsWith('Error:')) {
      setState(() {
        _decodedController.text = 'No data to decode';
      });
      return;
    }

    setState(() {
      _isDecoding = true;
    });
    
    try {
      // Parse FBP and LBP as decimal values (byte positions)
      final fbp = int.tryParse(_fbpController.text) ?? 0;
      final lbp = int.tryParse(_lbpController.text) ?? 15;

      String result;
      if (_selectedFormat == 'BIN') {
        result = BinaryConversion.toBinary(_resultController.text, fbp, lbp);
      } else if (_selectedFormat == 'ASCII') {
        result = BinaryConversion.toASCII(_resultController.text, fbp, lbp);
      } else {
        result = BinaryConversion.toHex(_resultController.text, fbp, lbp);
      }
      
      setState(() {
        _decodedController.text = result;
      });
      
    } catch (error) {
      setState(() {
        _decodedController.text = 'Decode error: $error';
      });
    } finally {
      setState(() {
        _isDecoding = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('DESFire Scanner'),
        backgroundColor: Colors.green,
        foregroundColor: Colors.white,
      ),
      body: SafeArea(
        child: Form(
          key: _formKey,
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(16.0),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // Header Card
                Card(
                  elevation: 4,
                  color: Colors.green[50],
                  child: Padding(
                    padding: const EdgeInsets.all(16.0),
                    child: Column(
                      children: [
                        const Icon(Icons.nfc, size: 48, color: Colors.green),
                        const SizedBox(height: 8),
                        const Text(
                          'DESFire Card Reader',
                          style: TextStyle(
                            fontSize: 20,
                            fontWeight: FontWeight.bold,
                            color: Colors.green,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          'Read data from DESFire cards with AES authentication',
                          style: TextStyle(
                            fontSize: 14,
                            color: Colors.green[700],
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 24),

                // Byte Position Row
                Row(
                  children: [
                    Expanded(
                      child: TextFormField(
                        controller: _fbpController,
                        decoration: const InputDecoration(
                          labelText: 'FBP (0-15)',
                          border: OutlineInputBorder(),
                          hintText: 'First byte',
                          prefixIcon: Icon(Icons.first_page),
                        ),
                        keyboardType: TextInputType.number,
                        validator: (value) => _validateBytePosition(value, 'FBP'),
                        inputFormatters: [
                          FilteringTextInputFormatter.digitsOnly,
                          LengthLimitingTextInputFormatter(2),
                        ],
                      ),
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: TextFormField(
                        controller: _lbpController,
                        decoration: const InputDecoration(
                          labelText: 'LBP (0-15)',
                          border: OutlineInputBorder(),
                          hintText: 'Last byte',
                          prefixIcon: Icon(Icons.last_page),
                        ),
                        keyboardType: TextInputType.number,
                        validator: (value) => _validateBytePosition(value, 'LBP'),
                        inputFormatters: [
                          FilteringTextInputFormatter.digitsOnly,
                          LengthLimitingTextInputFormatter(2),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),

                // FBP > LBP info card
                if (_fbpController.text.isNotEmpty && _lbpController.text.isNotEmpty)
                  Builder(
                    builder: (context) {
                      final fbp = int.tryParse(_fbpController.text);
                      final lbp = int.tryParse(_lbpController.text);
                      if (fbp != null && lbp != null && fbp > lbp) {
                        return Card(
                          color: Colors.amber.withOpacity(0.1),
                          child: Padding(
                            padding: const EdgeInsets.all(12.0),
                            child: Row(
                              children: [
                                const Icon(Icons.info, color: Colors.amber),
                                const SizedBox(width: 8),
                                Expanded(
                                  child: Text(
                                    'FBP > LBP: Data will be read in reverse order',
                                    style: TextStyle(
                                      color: Colors.amber[800],
                                      fontWeight: FontWeight.w500,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                        );
                      }
                      return const SizedBox.shrink();
                    },
                  ),
                const SizedBox(height: 16),

                // Application ID Input
                TextFormField(
                  controller: _applicationIdController,
                  decoration: const InputDecoration(
                    labelText: 'Application ID (6 hex chars)',
                    border: OutlineInputBorder(),
                    hintText: 'Enter 6-character hex application ID',
                    prefixIcon: Icon(Icons.apps),
                    helperText: 'Format: 0-9, A-F (case insensitive)',
                    errorMaxLines: 2,
                  ),
                  maxLength: 6,
                  validator: _validateApplicationId,
                  inputFormatters: [
                    FilteringTextInputFormatter.allow(RegExp(r'[0-9a-fA-F]')),
                    UpperCaseTextFormatter(),
                  ],
                ),
                const SizedBox(height: 16),

                // File ID Input
                TextFormField(
                  controller: _fileIdController,
                  decoration: const InputDecoration(
                    labelText: 'File ID (hex)',
                    border: OutlineInputBorder(),
                    hintText: 'Enter hex file ID',
                    prefixIcon: Icon(Icons.insert_drive_file),
                    helperText: 'Format: 0-9, A-F (case insensitive)',
                    errorMaxLines: 2,
                  ),
                  validator: _validateFileId,
                  inputFormatters: [
                    FilteringTextInputFormatter.allow(RegExp(r'[0-9a-fA-F]')),
                    UpperCaseTextFormatter(),
                  ],
                ),
                const SizedBox(height: 16),

                // Key Number Input
                TextFormField(
                  controller: _keyNumberController,
                  decoration: const InputDecoration(
                    labelText: 'Key Number (hex)',
                    border: OutlineInputBorder(),
                    hintText: 'Enter hex key number',
                    prefixIcon: Icon(Icons.vpn_key),
                    helperText: 'Format: 0-9, A-F (case insensitive)',
                    errorMaxLines: 2,
                  ),
                  validator: _validateKeyNumber,
                  inputFormatters: [
                    FilteringTextInputFormatter.allow(RegExp(r'[0-9a-fA-F]')),
                    UpperCaseTextFormatter(),
                  ],
                ),
                const SizedBox(height: 16),

                // Authentication Key Input with validation
                TextFormField(
                  controller: _authKeyController,
                  decoration: InputDecoration(
                    labelText: 'Authentication Key (32 hex chars)',
                    border: const OutlineInputBorder(),
                    hintText: 'Enter 32-character hex key',
                    prefixIcon: const Icon(Icons.security),
                    suffixIcon: IconButton(
                      icon: const Icon(Icons.clear),
                      onPressed: () => _authKeyController.clear(),
                      tooltip: 'Clear key',
                    ),
                    helperText: 'Format: 0-9, A-F (case insensitive)',
                    errorMaxLines: 2,
                  ),
                  maxLength: 32,
                  validator: _validateAuthKey,
                  inputFormatters: [
                    FilteringTextInputFormatter.allow(RegExp(r'[0-9a-fA-F]')),
                    UpperCaseTextFormatter(),
                  ],
                ),
                const SizedBox(height: 24),

                // DESFire Information Card
                Card(
                  elevation: 2,
                  child: Padding(
                    padding: const EdgeInsets.all(16.0),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'DESFire Information',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        const SizedBox(height: 16),
                        
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: Colors.grey[100],
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(color: Colors.grey[300]!),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Row(
                                children: [
                                  const Icon(Icons.info, size: 16, color: Colors.grey),
                                  const SizedBox(width: 8),
                                  const Text(
                                    'DESFire Protocol',
                                    style: TextStyle(
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 8),
                              Text(
                                '• Application selection with 6-byte AID\n'
                                '• AES-128 authentication\n'
                                '• Encrypted file reading\n'
                                '• Session key derivation',
                                style: TextStyle(
                                  fontSize: 12,
                                  color: Colors.grey[600],
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 24),

                // Scan Button with validation
                ElevatedButton(
                  onPressed: _isScanning ? null : () async {
                    // Validate form first
                    if (!_formKey.currentState!.validate()) {
                      _showValidationErrors();
                      return;
                    }

                    setState(() {
                      _isScanning = true;
                      _resultController.text = 'Scanning...';
                    });

                    try {
                      final desfireServices = DesfireNfcServices(debugMode: true);
                      final result = await desfireServices.readDesfire(
                        _applicationIdController.text,
                        _fileIdController.text,
                        _keyNumberController.text,
                        _authKeyController.text,
                      );
                      
                      setState(() {
                        if (result.isSuccess) {
                          _resultController.text = result.data!;
                        } else {
                          final errorMsg = result is DesfireError<String> ? result.message : null;
                          _resultController.text = errorMsg ?? 'Error: ${result.errorCode?.description} (${result.errorCode?.code})';
                        }
                        _decodedController.clear(); // Clear previous decoded data
                      });
                    } catch (e) {
                      setState(() {
                        _resultController.text = 'Error: $e';
                      });
                    } finally {
                      setState(() {
                        _isScanning = false;
                      });
                    }
                  },
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    backgroundColor: _isFormValid() ? Colors.green : Colors.grey,
                    foregroundColor: Colors.white,
                  ),
                  child: _isScanning
                      ? const Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            SizedBox(
                              width: 20,
                              height: 20,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                                valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                              ),
                            ),
                            SizedBox(width: 12),
                            Text(
                              'Scanning...',
                              style: TextStyle(fontSize: 18),
                            ),
                          ],
                        )
                      : const Text(
                          'Read DESFire Card',
                          style: TextStyle(fontSize: 18),
                        ),
                ),
                const SizedBox(height: 24),

                // Raw output area
                TextFormField(
                  controller: _resultController,
                  decoration: const InputDecoration(
                    labelText: 'Raw Data',
                    border: OutlineInputBorder(),
                    hintText: 'Raw scan data will appear here...',
                    prefixIcon: Icon(Icons.data_object),
                  ),
                  readOnly: true,
                  maxLines: 3,
                  style: const TextStyle(
                    fontSize: 12,
                    fontFamily: 'monospace',
                  ),
                ),
                const SizedBox(height: 24),

                // Decode section
                Row(
                  children: [
                    ElevatedButton(
                      onPressed: _isDecoding ? null : _decodeData,
                      child: _isDecoding
                          ? const SizedBox(
                              width: 16,
                              height: 16,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Text('Decode'),
                    ),
                    const SizedBox(width: 16),
                    DropdownButton<String>(
                      value: _selectedFormat,
                      items: _formats.map((String format) {
                        return DropdownMenuItem<String>(
                          value: format,
                          child: Text(format),
                        );
                      }).toList(),
                      onChanged: (String? newValue) {
                        if (newValue != null) {
                          setState(() {
                            _selectedFormat = newValue;
                          });
                        }
                      },
                    ),
                  ],
                ),
                const SizedBox(height: 16),

                // Decoded output area
                TextFormField(
                  controller: _decodedController,
                  decoration: const InputDecoration(
                    labelText: 'Decoded Data',
                    border: OutlineInputBorder(),
                    hintText: 'Decoded data will appear here...',
                    prefixIcon: Icon(Icons.translate),
                  ),
                  readOnly: true,
                  maxLines: 10,
                  style: const TextStyle(
                    fontSize: 12,
                    fontFamily: 'monospace',
                  ),
                ),
                const SizedBox(height: 24),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
