# TimeCapsule
TimeCapsule is a tool designed to securely transmit passphrases to Bitcoin wallets and other sensitive accounts using time-lock puzzles. This tool ensures that passphrases are accessible only after a predetermined period, providing a secure method for inheritance and delayed access to digital assets.

## Features

- **Secure Passphrase Storage**: Ensures that the passphrase is locked and can only be accessed after a specific amount of computation has been performed (computational time-lock) has elapsed.
- **Cryptography**: Utilizes AES encryption and time-lock puzzles based on repeated squaring to secure data.
- **Customizable Delay**: Users can set a specific delay period in seconds, after which the passphrase can be decrypted.  Users can and should adjust speed based on system they expect to either be attacked on or solved on (taking into consideration threat model).  Speed was baselined on 3.4 GHz Intel system.

## Installation on Windows

TimeCapsule can be built using VisualStudio, although that requires a little bit of configuration at this moment.  Will eventually update with VS Project file, and other build files for other platforms.

## Installation on Windows

```
brew install openssl
brew install nlohmann-json
gcc -std=c++11 -o timecapsule timecapsule_mac.cpp -I/opt/homebrew/Cellar/openssl@3/3.3.0/include -I/opt/homebrew/opt/nlohmann-json/include -L/opt/homebrew/Cellar/openssl@3/3.3.0/lib -lssl -lcrypto -lstdc++
```


## Creating a New TimeLock Puzzle

1. Run the code and select option 1 to create a new puzzle.
2. Enter the desired time in seconds that the puzzle should remain locked.
3. Wait as puzzle is "charged"
4. Enter password that you want timelocked in puzzle.
5. The script will generate a puzzle and save it in a file named `puzzle.json`.

### Solving a Puzzle

1. Rerun and select option 2 to crack current puzzle saved as 'puzzle.json'.

## How It Works

TimeCapsule encrypts a given passphrase using AES encryption. The encryption key is locked within a time-lock puzzle, which requires performing a computationally intensive task that cannot be sped up by parallel processing. This task involves repeatedly squaring a number modulo a large number, a process that must be repeated a specific number of times determined by the desired delay.

## Security Considerations

- Set SPEED according to threat model
- Keep the `puzzle.json` file secure to prevent unauthorized access before the time-lock expires.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
