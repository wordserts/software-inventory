"""
Main entry point for Software Inventory Extension
"""

from .extension import SoftwareInventoryExtension

def main():
    """Entry point for the extension"""
    SoftwareInventoryExtension().run()

if __name__ == '__main__':
    main()
