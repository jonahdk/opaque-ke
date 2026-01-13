import importlib.machinery
import importlib.util
import sys
from pathlib import Path


def _load_extension():
    name = __name__
    package_dir = Path(__file__).resolve().parent
    for suffix in importlib.machinery.EXTENSION_SUFFIXES:
        candidate = package_dir / f"{name}{suffix}"
        if candidate.exists():
            spec = importlib.util.spec_from_file_location(name, candidate)
            if spec is None or spec.loader is None:
                raise ImportError(f"Failed to load extension module from {candidate}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            return module
    raise ImportError("opaque_ke extension module not found; run 'maturin develop'")


_module = _load_extension()
# Mirror the extension module so `import opaque_ke` behaves like the native module.
globals().update(_module.__dict__)
