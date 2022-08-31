
A small CLI tool to download a file from servers running Crowdstrike's LFO service.  
You must know a file's remote path on your target LFO server to download it.

This tool is provided with no warranty and is expressly intended for research purposes.  
By default, the CLI connects to the public Crowdstrike servers.  
Please avoid sending unusual or overly fast requests to public servers in a way that could impact quality of service for other users.

Example usage:

```
lfo-client download -l KernelModuleArchiveExt14107.meta /osfm/linux/e3c6cd60bb18e9271fa2e4e7739964cd9dc2f4a90a95da21febe83b639d5e0f3
```

Help summary:

```
lfo-client

SUBCOMMANDS:
    download         Download a file from an LFO server
    help             Print this message or the help of the given subcommand(s)
    parse-channel    Parse a "channel file" and try to show any download records inside

OPTIONS:
    -h, --help    Print help information
```
