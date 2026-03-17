# Claude for NeXTSTEP

A native Claude AI console client for NeXTSTEP 3.3, running on a NeXTstation Turbo Color (68040 @ 33MHz).

This project brings modern AI to vintage hardware — a C client that speaks directly to the Claude API over TLS 1.2, compiled with gcc 2.5.8 from 1993.

```
╔══════════════════════════════════════╗
║  Claude for NeXTSTEP                 ║
╚══════════════════════════════════════╝

you> Hello from 1993!

claude> Hello! It's remarkable to be running
on a NeXTstation — the machine that gave us
the World Wide Web. What shall we discuss?

you> _
```

## Hardware

- **NeXTstation Turbo Color** — Motorola 68040 @ 33MHz, running NeXTSTEP 3.3


## How It Works

The NeXTstation connects directly to the Claude API (`api.anthropic.com`) over HTTPS using [Crypto Ancienne](https://github.com/classilla/cryanc), a TLS library designed for vintage systems. No proxy or middleware needed — the 68040 handles TLS 1.2 natively.

```
NeXTstation (68040)  ──── HTTPS/TLS 1.2 ────►  api.anthropic.com
     192.168.1.2                                     Claude API
       
```

TLS handshake takes ~10 seconds on the 33MHz 68040. A small price for direct, encrypted communication from a 1993 machine.

## Building

On the NeXTstation:

```sh
cc -O -o claude claude.c
```

The build takes ~6 minutes on the 68040 (cryanc is a 1.4MB single-file TLS library compiled inline).

## Usage

```sh
./claude
```

Requires a Claude API key. Set it in a config file or pass at startup.

## Project Structure

```
claude.c          — Main client source (includes cryanc for TLS)
cryanc.c          — Crypto Ancienne TLS library (vendored)
cryanc.h          — Crypto Ancienne header (vendored)
```
## Credits & Acknowledgments

### Authors
- **ARNLTony** — Project creator, hardware setup, integration
- **Claude (Anthropic)** — AI pair programmer, client code, architecture

### Key Dependencies
- **[Crypto Ancienne (cryanc)](https://github.com/classilla/cryanc)** by Cameron Kaiser — TLS 1.2/1.3 library for vintage systems. This project would not be possible without it. Crypto Ancienne is specifically designed for pre-C99 compilers and old hardware, with explicit support for NeXTSTEP 3.3 on 68K.
- **[Claude API](https://docs.anthropic.com/en/docs/api)** by Anthropic — The AI backend

### Tools & Infrastructure
- **[Claude Code](https://claude.ai/claude-code)** — Anthropic's CLI tool, used for all development
- **NeXTSTEP 3.3** (NeXT Computer, 1993) — The operating system
- **gcc 2.5.8** (cc-437.2.6) — The compiler, vintage 1993

### Inspiration
- The NeXT community at [nextcomputers.org](https://www.nextcomputers.org/)
- Cameron Kaiser's work on [retrocomputing internet access](http://oldvcr.blogspot.com/2020/11/fun-with-crypto-ancienne-tls-for.html)
- The broader vintage computing community pushing old hardware to do new things

## License

MIT License. See [LICENSE](LICENSE) for details.

Crypto Ancienne is licensed under its own terms — see [cryanc repo](https://github.com/classilla/cryanc) for details.
