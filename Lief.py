import lief
from alerting import log_threat

def inspect_pe(file_path):
    try:
        binary = lief.parse(file_path)
        if not binary:
            print(f"[ERROR] Failed to parse binary: {file_path}")
            return False

        optional_header = binary.optional_header

        print(f"File format: {binary.format}")
        print(f"Entry point: {hex(binary.entrypoint)}")

        dos_header = binary.dos_header
        print(f"Magic number: {hex(dos_header.magic)}")

        print("Sections:")
        for section in binary.sections:
            print(f" - {section.name}, Size: {section.size}")

        print("Imported Libraries:")
        for lib in binary.imports:
            print(f" - {lib.name}")

        print("Exported Functions:")
        for function in binary.exported_functions:
            print(f" - {function}")

        # Example check: alert if there are no imported libraries (which can be suspicious)
        if len(binary.imports) == 0:
            log_threat("N/A", "local", "LIEF_PE_Inspector", "medium", 0,
                       f"No imports found in {file_path}")

        # Add a new section with NOPs (0x90) - optional
        new_section = lief.PE.Section("new_section")
        new_section.content = [0x90] * 100
        new_section.virtual_address = binary.optional_header.size_of_image

        binary.add_section(new_section)
        modified_filename = "modified_" + file_path
        binary.write(modified_filename)
        print(f"Modified binary saved as {modified_filename}")

        return True

    except Exception as e:
        print(f"[ERROR] Exception during PE inspection: {e}")
        log_threat("N/A", "local", "LIEF_PE_Inspector_Error", "low", 0, str(e))
        return False
