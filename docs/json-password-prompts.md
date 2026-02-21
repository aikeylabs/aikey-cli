# JSON Mode Password Prompts

## Overview

When using `--json` mode, the CLI maintains structured JSON output while still supporting interactive password prompts. This allows programmatic consumers to handle password input properly.

## How It Works

When the CLI needs a password in JSON mode, it:

1. Outputs a JSON prompt object to stdout
2. Reads the password from stdin
3. Continues with the operation
4. Outputs the final result as JSON

## Prompt Format

```json
{
  "type": "prompt",
  "prompt_type": "password",
  "message": "Enter vault password: "
}
```

## Example: Change Password

### Input
```bash
printf "oldpass\nnewpass\nnewpass\n" | ak change-password --json
```

### Output
```json
{"type":"prompt","prompt_type":"password","message":"Enter current vault password: "}
{"type":"prompt","prompt_type":"password","message":"Enter new vault password: "}
{"type":"prompt","prompt_type":"password","message":"Confirm new vault password: "}
{"success":true,"message":"Password changed successfully"}
```

## Handling in Code

### Python Example
```python
import subprocess
import json

def change_password(old_pass, new_pass):
    proc = subprocess.Popen(
        ['ak', 'change-password', '--json'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    # Send passwords
    input_data = f"{old_pass}\n{new_pass}\n{new_pass}\n"
    stdout, stderr = proc.communicate(input=input_data)

    # Parse output lines
    for line in stdout.strip().split('\n'):
        data = json.loads(line)
        if data.get('type') == 'prompt':
            # Log or handle prompt
            print(f"Prompt: {data['message']}")
        elif 'success' in data:
            # Final result
            return data
```

### JavaScript Example
```javascript
const { spawn } = require('child_process');

async function changePassword(oldPass, newPass) {
    return new Promise((resolve, reject) => {
        const proc = spawn('ak', ['change-password', '--json']);

        let output = '';
        proc.stdout.on('data', (data) => {
            output += data.toString();
        });

        proc.on('close', (code) => {
            const lines = output.trim().split('\n');
            const results = lines.map(line => JSON.parse(line));

            // Filter out prompts, get final result
            const result = results.find(r => r.success !== undefined);
            resolve(result);
        });

        // Send passwords
        proc.stdin.write(`${oldPass}\n${newPass}\n${newPass}\n`);
        proc.stdin.end();
    });
}
```

## Commands That Prompt

The following commands may prompt for passwords in JSON mode:

- `init` - Prompts for initial vault password
- `add` - Prompts for vault password if not provided
- `get` - Prompts for vault password if not provided
- `list` - Prompts for vault password if not provided
- `delete` - Prompts for vault password if not provided
- `update` - Prompts for vault password if not provided
- `change-password` - Prompts for old password, new password, and confirmation
- `exec` / `run` - Prompts for vault password if not provided

## Best Practices

1. **Parse Line by Line**: Each JSON object is on its own line
2. **Filter by Type**: Distinguish between prompts and results using the `type` field
3. **Handle Prompts**: Log or display prompt messages to users
4. **Pipe Passwords**: Use stdin to provide passwords programmatically
5. **Check Exit Codes**: Always verify the process exit code for errors

## Error Handling

If an error occurs during password prompts, the CLI will output an error JSON object:

```json
{
  "success": false,
  "error": "Password verification failed"
}
```

The process will exit with a non-zero exit code.
