#! /usr/bin/env python3
import atheris
import sys
import fuzz_helpers
import random

with atheris.instrument_imports(include=["georinex"]):
    import georinex as gr

value_err_matchers = ['valid header', 'RINEX', 'unknown file', 'NAV', 'rinex']
def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        test = fdp.ConsumeIntInRange(0, 4)

        if test == 0:
            with fdp.ConsumeMemoryFile(all_data=True, as_bytes=False) as f:
                f.name = 'test.10o'
                gr.load(f)
        elif test == 1:
            with fdp.ConsumeMemoryFile(all_data=True, as_bytes=False) as f:
                gr.rinexheader(f)
        elif test == 2:
            with fdp.ConsumeMemoryFile(all_data=True, as_bytes=False) as f:
                gr.rinexinfo(f)
        elif test == 3:
            with fdp.ConsumeMemoryFile(all_data=True, as_bytes=False) as f:
                gr.rinexobs(f)
        elif test == 3:
            with fdp.ConsumeMemoryFile(all_data=True, as_bytes=False) as f:
                gr.rinexnav(f)
        elif test == 4:
            with fdp.ConsumeMemoryFile(all_data=True, as_bytes=False) as f:
                gr.gettime(f)
    except (AssertionError, KeyError, IndexError,) as e:
        if random.random() > 0.90:
            raise e
        return -1
    except LookupError as e:
        if 'RINEX' in str(e):
            return -1
        if random.random() > 0.99:
            raise e
    except ValueError as e:
        if any(matcher in str(e) for matcher in value_err_matchers):
            return -1
        if random.random() > 0.99:
            raise e



def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
