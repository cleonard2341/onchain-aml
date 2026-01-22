# Chain Scanner

**On-Chain AML Pattern Detector**

A local/offline AML pattern detection tool for cryptocurrency transactions. Supports Ethereum and Bitcoin, multiple data input methods, and provides both CLI and library interfaces.

## Features

- **Multi-chain support**: Ethereum and Bitcoin
- **Multiple data sources**: JSON/CSV files, API (Etherscan), or local node
- **Comprehensive detection**: Mixers, sanctions, structuring, layering, privacy coins, bridges
- **Risk scoring**: 0-100 score with LOW/MEDIUM/HIGH/CRITICAL classification
- **Flexible output**: Terminal, JSON, or CSV reports
- **Local/offline**: All analysis runs locally - no data sent to external servers
- **Extensible**: Easy to add new detectors and data sources

## Installation

```bash
pip install chain-scanner
```

Or install from source:

```bash
git clone https://github.com/example/chain-scanner.git
cd chain-scanner
pip install -e .
```

## Quick Start

### As a Library

```python
from chain_scanner import Scanner

# Create scanner for Ethereum
scanner = Scanner(chain="ethereum")

# Scan an address (without fetching - just check against lists)
result = scanner.scan_address("0x742d35Cc6634C0532925a3b844Bc9e7595f...", fetch_transactions=False)

# Scan transactions from a file
result = scanner.scan_file("transactions.json")

# Check the results
print(f"Risk Score: {result.risk_score}/100")
print(f"Risk Level: {result.risk_level}")
print(f"Summary: {result.summary}")

for flag in result.flags:
    print(f"  [{flag.severity}] {flag.type}: {flag.details}")
```

### Command Line

```bash
# Scan an address
chain-scanner scan 0x742d35Cc6634C0532925a3b844Bc9e7595f... --chain eth

# Scan from a file
chain-scanner scan-file transactions.json

# Check against sanctions list only
chain-scanner check-sanctions 0x8589427373D6D84E98730D7795D8f6f8731FDA16

# Generate JSON report
chain-scanner scan-file data.json --output report.json --output-format json

# List available detectors
chain-scanner list-detectors
```

## Detection Modules

| Detector | Description | Signals |
|----------|-------------|---------|
| **Sanctions** | OFAC/blocklist match | Address appears on sanctions list |
| **Mixer** | Known mixer services | Tornado Cash, Wasabi, CoinJoin, etc. |
| **Structuring** | Transaction splitting | Multiple txs just below reporting thresholds |
| **Layering** | Rapid fund movement | Funds hopping 3+ addresses within 48 hours |
| **Privacy Coins** | Anonymity-enhanced | RAILGUN, Aztec, privacy token bridges |
| **Bridges** | Cross-chain movement | Wormhole, Multichain, THORChain, etc. |

## Risk Scoring

Each scan returns a comprehensive risk assessment:

```python
{
    "address": "0x...",
    "risk_score": 78,          # 0-100
    "risk_level": "HIGH",      # LOW/MEDIUM/HIGH/CRITICAL
    "flags": [
        {
            "type": "MIXER",
            "severity": "HIGH",
            "details": "Tornado Cash interaction",
            "tx_hash": "0x..."
        },
        {
            "type": "STRUCTURING",
            "severity": "MEDIUM",
            "details": "5 transactions of $9,800-$9,950"
        }
    ],
    "summary": "High risk patterns detected: mixer usage, potential structuring"
}
```

### Risk Levels

- **LOW** (0-25): Minor or no risk indicators
- **MEDIUM** (26-50): Some risk indicators present
- **HIGH** (51-75): Significant risk patterns detected
- **CRITICAL** (76-100): Severe risk including sanctions matches

## Data Sources

### File Input

```python
# JSON file
result = scanner.scan_file("transactions.json")

# CSV file
result = scanner.scan_file("transactions.csv")

# With explicit format
result = scanner.scan_file("data.txt", format="json")
```

### API Source (Etherscan)

```python
from chain_scanner import Scanner

scanner = Scanner(chain="ethereum")
scanner.use_api_source(api_key="YOUR_ETHERSCAN_API_KEY")

result = scanner.scan_address("0x...", fetch_transactions=True, limit=100)
```

Or via CLI:

```bash
export ETHERSCAN_API_KEY=your_key
chain-scanner scan 0x... --api-key $ETHERSCAN_API_KEY
```

### Custom Transaction Data

```python
from chain_scanner import Scanner, Transaction
from decimal import Decimal
from datetime import datetime

transactions = [
    Transaction(
        hash="0xabc...",
        chain="ethereum",
        from_address="0x111...",
        to_address="0x222...",
        value=Decimal("1.5"),
        timestamp=datetime.now(),
    ),
    # ... more transactions
]

scanner = Scanner(chain="ethereum")
result = scanner.scan_transactions(transactions)
```

## Configuration

Create a configuration file:

```json
{
  "structuring": {
    "threshold_usd": 10000,
    "margin_percent": 5,
    "min_transactions": 3
  },
  "layering": {
    "min_hops": 3,
    "time_window_hours": 48
  },
  "risk_weights": {
    "sanctions": 100,
    "mixer": 80,
    "privacy_coin": 60,
    "bridge": 40
  }
}
```

Use it:

```bash
chain-scanner --config config.json scan 0x...
```

```python
from chain_scanner import Scanner, ScannerConfig

config = ScannerConfig.from_file("config.json")
scanner = Scanner(chain="ethereum", config=config)
```

## Output Formats

### Terminal (default)

Rich formatted output with colors and tables.

### JSON

```bash
chain-scanner scan-file data.json --output-format json
```

### CSV

```bash
chain-scanner scan-file data.json --output-format csv --output report.csv
```

## File Formats

### Input JSON Format

```json
{
  "transactions": [
    {
      "hash": "0x...",
      "from": "0x...",
      "to": "0x...",
      "value": "1000000000000000000",
      "blockNumber": 15000000,
      "timeStamp": "1672531200"
    }
  ]
}
```

Or a simple array:

```json
[
  {"hash": "0x...", "from": "0x...", "to": "0x...", "value": "1000000000000000000"}
]
```

### Input CSV Format

```csv
hash,from,to,value,blockNumber,timeStamp
0x...,0x...,0x...,1000000000000000000,15000000,1672531200
```

## Development

### Setup

```bash
git clone https://github.com/example/chain-scanner.git
cd chain-scanner
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest tests/ -v
```

### Code Style

```bash
black chain_scanner/
ruff check chain_scanner/
mypy chain_scanner/
```

## Adding Custom Detectors

```python
from chain_scanner.detectors.base import Detector, DetectionResult, RiskLevel

class CustomDetector(Detector):
    name = "custom"
    description = "My custom detector"
    default_severity = RiskLevel.MEDIUM

    def analyze_transactions(self, transactions, target_address=None):
        flags = []

        for tx in transactions:
            if self._is_suspicious(tx):
                flags.append(self.create_flag(
                    details="Suspicious pattern detected",
                    tx_hash=tx.hash,
                    severity=RiskLevel.HIGH,
                ))

        return DetectionResult(
            detector_name=self.name,
            flags=flags,
        )

    def _is_suspicious(self, tx):
        # Your detection logic here
        return False
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for informational and research purposes only. It should not be used as the sole basis for compliance decisions. Always consult with legal and compliance professionals for AML/KYC requirements.

The address lists included are samples for demonstration. For production use:
- Update sanctions lists regularly from official OFAC sources
- Maintain current mixer and bridge address databases
- Validate detection patterns against your compliance requirements

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## Support

- GitHub Issues: Report bugs and request features
- Documentation: See the `/docs` folder for detailed guides
