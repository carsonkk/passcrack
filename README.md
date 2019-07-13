# passcrack

> Simple password cracking script based on a breadth-first manipulation of a given search dictionary

## About

This program attempts to break password hashes created through DES, MD5, SHA-256, and SHA-512 using a dictionary/brute-force hybrid attack with increasing levels of complexity. It takes these parameters:

- A file name containing a list of single word, newline seperated words to use as a base "dictionary". These words are subsequently manipulated based on common password manipulations and substitutions
- An integer value representing an algorithm id:
  - 1 corresponds to MD5
  - 5 corresponds to SHA-256
  - 6 corresponds to SHA-512
  - Any other value 0 or greater corresponds to DES (don't use negative values)
- A given salt value
- A given hash value

## Example Usage

```console
[user@laptop]$ python passcrack.py dictionary.txt 5 aBD123cdE ADH/D30llsWnrTJTKJBxvaztshXoNbX4J.hakVNp1p0
```

## Setup & Search Algorithm

The program will format the algorithm id, salt, and hash for validity checking. It will then begin to parse all the way through the dictionary where there are multiple "levels" of manipulation applied to the entries. As the level increases, the number of variations and their complexity increases. The following information is assumed about the target password(s):

- They may be based on common english words
- They may be related to the user name
- They may use number/symbol substitutions (i.e. '3' for 'E', or '!' for 'i')
- They may be based on different permutations of character order
- They may contain random characters from a limited set
- They are each a minimum length of 6 characters long

The subsequent levels of manipulation applied to the entries include the following:

- Level 1: Variations of letter casing
- Level 2: Combinations of different number substitutions for corresponding letters
- Level 3: Various character ordering permutations
- Level 4: Combinations of different symbol substitutions for corresponding letters
- Level 5: Including common characters in each possible index and uncommon characters at the begining and/or end of the word

If the password is still not found after searching through these five levels, it will ascend to level 6, and end up in a "dumb" brute force search in which it attempts all possible combinations of a limited set of characters, starting with passwords of length 6 and continuing up until a length of 14 (or until either the computer looses power or the universe ends, whichever comes first).

When the script ends, it will either report the discovered password or that an unexpected error has occurred. If a password is found, it will print it to the console, append it to a locally saved text file, and send it to a specified email. If a password is not found, it will report an error in the console and send an error notification to the specified email.

## Disclaimer

*This program was created purely as an educational exercise while studying cryptography and security. It is not intended to be used for any purpose other than self-learning, malicious or otherwise. It also isn't very well written- you can find much better, proper tools out there. Just saying*