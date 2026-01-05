from setuptools import setup, find_packages

setup(
    name="idalib",
    version="0.1.0",
    description="A library for exporting IDA Pro databases to SQLite",
    author="Your Name",
    packages=find_packages(),
    py_modules=["export_binary_db"],
    install_requires=[
        # List dependencies if any (e.g., standard libraries are usually not listed)
        # "some-package>=1.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
