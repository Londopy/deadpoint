# deadpoint demo recording script for charmbracelet/vhs.
#
#   pip install deadpoint          # or: pip install -e .
#   go install github.com/charmbracelet/vhs@latest   # (or: brew install vhs)
#   vhs docs/demo.tape             # writes docs/demo.gif
#
# Alternatively record with asciinema:  asciinema rec docs/demo.cast

Output docs/demo.gif

Set FontSize 16
Set Width 1100
Set Height 640
Set Theme "Dracula"
Set Padding 18
Set TypingSpeed 40ms

# Generate 700 MT19937 "session tokens" to audit.
Type "python -c \"import random; r=random.Random(2026); open('tokens.txt','w').write(chr(10).join(hex(r.getrandbits(32)) for _ in range(700)))\""
Enter
Sleep 800ms

Type "deadpoint analyze tokens.txt --fmt hex --width 32"
Enter
Sleep 2s

Type "deadpoint predict tokens.txt --fmt hex --forward 5 --backward 3"
Enter
Sleep 2500ms

Type "deadpoint report tokens.txt --fmt hex --forward 3"
Enter
Sleep 3500ms
