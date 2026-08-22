"""Entry point for PyInstaller bundles. Imports the package, then runs main()."""
import sys
from treadmark.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
