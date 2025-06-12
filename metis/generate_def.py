import pefile

dll = pefile.PE('unicode_original.dll')

print("EXPORTS")
for export in dll.DIRECTORY_ENTRY_EXPORT.symbols:
    if export.name:
        print('{}=unicode_original.{} @{}'.format(export.name.decode(), export.name.decode(), export.ordinal))
