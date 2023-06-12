from setuptools import setup

setup(
   name="pefile-stubs",
   version="0.1",
   package_data={"pefile-stubs": ["__init__.pyi", "ordlookup/__init__.pyi"]},
   packages=["pefile-stubs"]
)