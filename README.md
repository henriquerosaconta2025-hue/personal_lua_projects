# personal_lua_projects

Personal LuaJIT/Linux libraries and experiments.

This repository contains some of my Lua/LuaJIT projects, mostly focused on:

- terminal/xterm utilities
- networking
- Linux low-level APIs
- FFI experiments
- system-related tools

## Libraries

### `xterm.lua`
A terminal toolkit for LuaJIT with:

- mouse input
- RGB colors
- raw terminal mode
- polling / timeout reads
- clipboard support (OSC52)
- hyperlinks
- alternate screen
- terminal utilities

### `net.lua`
Networking library for LuaJIT with low-level socket access and some high-level helpers.

## Status

Actively developed. APIs are intended to remain backwards compatible.

## License

MIT
