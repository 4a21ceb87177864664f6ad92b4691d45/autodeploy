rhel-autodeploy/
├── bin/
│   └── autodeploy.py           # Main orchestrator CLI
├── lib/
│   ├── config.py               # Configuration schema
│   └── logger.py               # Structured logging
├── modules/
│   ├── harden.py               # First-boot hardening (runs on target)
│   └── validate.py             # Post-deploy validation (runs on target)
├── templates/
│   ├── user-data.yaml.j2       # Cloud-init payload
│   ├── met a-data.yaml.j2       # Cloud-init metadata
│   └── network-config.yaml.j2  # Cloud-init network config
├── config.example.yaml         # Example configuration
├── requirements.txt            # Python dependencies
└── README.md                   # Documentation
