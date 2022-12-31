#! /usr/bin/env python3
import atheris
import sys
import fuzz_helpers
import random

with atheris.instrument_imports(include=["georinex"]):
    import georinex as gr

value_err_matchers = ['valid header', 'RINEX', 'unknown file']
def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        with fdp.ConsumeMemoryFile(all_data=True, as_bytes=False) as f:
            f.name = 'test.10o'
            gr.load(f)
    except (AssertionError, KeyError):
        return -1
    except IndexError as e:
        if random.random() > 0.99:
            raise e
        return -1
    except LookupError as e:
        if 'RINEX' in str(e):
            return -1
        raise e
    except ValueError as e:
        if any(matcher in str(e) for matcher in value_err_matchers):
            return -1
        raise



def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
