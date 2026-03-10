"""MCP Server for NeXTSTEP telnet access via T410 gateway."""

import socket
import time
import re
import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("nextstep")

# Connection settings — read from environment variables
T410_HOST = os.environ.get("NEXT_T410_HOST", "192.168.2.46")
T410_PORT = int(os.environ.get("NEXT_T410_PORT", "8023"))
NEXT_USER = os.environ.get("NEXT_USER", "tony")
NEXT_PASS = os.environ.get("NEXT_PASS", "")
NEXT_ROOT_PASS = os.environ.get("NEXT_ROOT_PASS", "")

_sock = None
_logged_in = False
_last_debug_log = []


def _recv_all(sock, timeout=2.0):
    """Read all available data from socket."""
    sock.setblocking(False)
    data = b""
    end_time = time.time() + timeout
    while time.time() < end_time:
        try:
            chunk = sock.recv(4096)
            if chunk:
                data += chunk
                end_time = time.time() + 0.5  # extend timeout on data
            else:
                break
        except BlockingIOError:
            time.sleep(0.1)
        except Exception:
            break
    sock.setblocking(True)
    return data


def _send(sock, text):
    """Send text over socket."""
    sock.sendall(text.encode("ascii"))


def _respond_to_telnet_negotiation(sock, data):
    """Reply to telnet DO/DONT/WILL/WONT requests so the server proceeds."""
    i = 0
    while i < len(data) - 2:
        if data[i:i+1] == b'\xff':
            cmd = data[i+1:i+2]
            opt = data[i+2:i+3]
            if cmd == b'\xfd':  # DO -> reply WILL for terminal type (24), WONT for others
                if opt == b'\x18':  # terminal type
                    sock.sendall(b'\xff\xfb\x18')  # WILL terminal type
                else:
                    sock.sendall(b'\xff\xfc' + opt)  # WONT
            elif cmd == b'\xfb':  # WILL -> reply DO
                sock.sendall(b'\xff\xfd' + opt)
            i += 3
        else:
            i += 1


def _strip_telnet_negotiation(data):
    """Remove telnet IAC negotiation bytes."""
    result = b""
    i = 0
    while i < len(data):
        if data[i:i+1] == b'\xff' and i + 1 < len(data):
            if data[i+1:i+2] in (b'\xfb', b'\xfc', b'\xfd', b'\xfe'):
                i += 3  # IAC WILL/WONT/DO/DONT option
                continue
            elif data[i+1:i+2] == b'\xfa':
                # Subnegotiation, skip until IAC SE
                j = i + 2
                while j < len(data) - 1:
                    if data[j:j+2] == b'\xff\xf0':
                        j += 2
                        break
                    j += 1
                i = j
                continue
            elif data[i+1:i+2] == b'\xff':
                result += b'\xff'
                i += 2
                continue
            else:
                i += 2
                continue
        result += data[i:i+1]
        i += 1
    return result


def _wait_for(sock, prompt, timeout=10):
    """Read from socket until prompt string appears or timeout."""
    data = b""
    end_time = time.time() + timeout
    while time.time() < end_time:
        try:
            sock.setblocking(False)
            chunk = sock.recv(4096)
            if chunk:
                data += chunk
                # Respond to any telnet negotiation inline
                _respond_to_telnet_negotiation(sock, chunk)
                # Handle terminal type subnegotiation (SB 24 SEND SE)
                if b'\xff\xfa\x18\x01\xff\xf0' in chunk:
                    # Reply: SB TERMINAL-TYPE IS VT100 SE
                    sock.sendall(b'\xff\xfa\x18\x00VT100\xff\xf0')
                text = _strip_telnet_negotiation(data).decode("ascii", errors="replace")
                if prompt in text:
                    sock.setblocking(True)
                    return data
            else:
                break
        except BlockingIOError:
            time.sleep(0.2)
        except Exception:
            break
    sock.setblocking(True)
    return data


def _get_connection():
    """Get or create connection to NeXT via T410 socat."""
    global _sock, _logged_in

    if _sock is not None:
        try:
            _send(_sock, "\n")
            time.sleep(0.3)
            _recv_all(_sock, 0.5)
            return _sock
        except Exception:
            _sock = None
            _logged_in = False

    _debug_log = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((T410_HOST, T410_PORT))
    _debug_log.append("Connected to T410")

    # Handle initial telnet negotiation
    time.sleep(1)
    initial = _recv_all(sock, 2)
    _debug_log.append(f"Initial bytes: {repr(initial[:80])}")
    _respond_to_telnet_negotiation(sock, initial)

    # Wait for login prompt
    data = _wait_for(sock, "login:", timeout=10)
    text = _strip_telnet_negotiation(data).decode("ascii", errors="replace")
    _debug_log.append(f"Login banner: {repr(text[:200])}")

    # Send username
    _send(sock, NEXT_USER + "\r\n")
    data = _wait_for(sock, "Password:", timeout=5)
    text = _strip_telnet_negotiation(data).decode("ascii", errors="replace")
    _debug_log.append(f"After username: {repr(text[:200])}")

    # Send tony's password
    _send(sock, NEXT_PASS + "\r\n")
    # Wait for either TERM prompt or shell prompt
    data = _wait_for(sock, "#", timeout=10)
    text = _strip_telnet_negotiation(data).decode("ascii", errors="replace")
    _debug_log.append(f"After password: {repr(text[:200])}")

    if "TERM" in text:
        # Handle TERM prompt — send vt100
        _send(sock, "vt100\r\n")
        time.sleep(2)
        _recv_all(sock, 2)

    # Su to root
    _send(sock, "su root\r\n")
    data = _wait_for(sock, "#", timeout=5)
    text = _strip_telnet_negotiation(data).decode("ascii", errors="replace")
    _debug_log.append(f"After su root: {repr(text[:200])}")

    if "Password:" in text or "password:" in text:
        _send(sock, NEXT_ROOT_PASS + "\n")
        time.sleep(1)
        _recv_all(sock, 1)

    # Clear buffer
    _send(sock, "\n")
    time.sleep(0.5)
    _recv_all(sock, 0.5)

    # Store debug log for retrieval
    global _last_debug_log
    _last_debug_log = _debug_log

    _sock = sock
    _logged_in = True
    return sock


def _clean_output(raw):
    """Remove ANSI escape codes and clean up output."""
    raw = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', raw)
    raw = re.sub(r'\r\n', '\n', raw)
    raw = re.sub(r'\r', '', raw)
    return raw.strip()


@mcp.tool()
def run_command(command: str) -> str:
    """Execute a command on the NeXTSTEP machine and return output.

    Args:
        command: The shell command to execute on the NeXT.
    """
    try:
        sock = _get_connection()

        # Clear any pending output
        _recv_all(sock, 0.3)

        # Send command
        _send(sock, command + "\r\n")

        # Wait for output
        time.sleep(2)
        output = _recv_all(sock, 3)

        result = _strip_telnet_negotiation(output).decode("ascii", errors="replace")
        result = _clean_output(result)

        # Remove the command echo from output
        lines = result.split("\n")
        if lines and command in lines[0]:
            lines = lines[1:]

        # Remove trailing prompt
        cleaned = []
        for line in lines:
            if re.match(r"localhost:\d+#", line.strip()):
                continue
            cleaned.append(line)

        return "\n".join(cleaned).strip() or "(no output)"

    except Exception as e:
        import traceback
        global _sock, _logged_in
        _sock = None
        _logged_in = False
        return f"Error: {str(e)}\n{traceback.format_exc()}"


@mcp.tool()
def set_root_password(password: str) -> str:
    """Set the root password used for su root on the NeXT.

    Args:
        password: The root password for the NeXT machine.
    """
    global NEXT_ROOT_PASS, _sock, _logged_in
    NEXT_ROOT_PASS = password
    if _sock:
        try:
            _sock.close()
        except Exception:
            pass
    _sock = None
    _logged_in = False
    return "Root password set. Will use on next connection."


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Write content to a file on the NeXT machine.

    Args:
        path: The file path on the NeXT.
        content: The content to write.
    """
    try:
        sock = _get_connection()

        # Clear buffer
        _recv_all(sock, 0.3)

        # Use cat with heredoc to write file
        _send(sock, f"cat > {path} << 'MCPEOF'\n")
        time.sleep(0.3)

        for line in content.split("\n"):
            _send(sock, line + "\n")
            time.sleep(0.05)

        _send(sock, "MCPEOF\n")
        time.sleep(1)
        _recv_all(sock, 1)

        return f"File written to {path}"

    except Exception as e:
        global _sock, _logged_in
        _sock = None
        _logged_in = False
        return f"Error: {str(e)}"


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the NeXT machine.

    Args:
        path: The file path on the NeXT to read.
    """
    return run_command(f"cat {path}")


@mcp.tool()
def reconnect() -> str:
    """Force close the current telnet session and reconnect fresh."""
    global _sock, _logged_in
    if _sock:
        try:
            _sock.close()
        except Exception:
            pass
    _sock = None
    _logged_in = False
    try:
        sock = _get_connection()
        return "Reconnected successfully."
    except Exception as e:
        return f"Reconnect failed: {str(e)}"


@mcp.tool()
def debug_connection() -> str:
    """Test the connection to the NeXT and return debug info."""
    try:
        sock = _get_connection()
        log = _last_debug_log if _last_debug_log else ['(no debug log - was already connected)']
        return "\n".join(log)
    except Exception as e:
        import traceback
        return f"Connection failed: {str(e)}\n{traceback.format_exc()}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
