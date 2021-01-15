"""
Flask-AWSCognito
-------------

User authentication with AWS Cognito for Flask
"""
from setuptools import setup, find_packages

tests_require = ["pytest", "pytest-mock", "pytest-flask"]

with open("README.md", "r") as fh:
    long_description = fh.read()


setup(
    name="Flask-AWSCognito",
    version="1.2.8",
    url="https://github.com/billdry/Flask-AWSCognito/",
    license="MIT",
    author="Bill Dry",
    author_email="bdry@amazon.com",
    description="Authenticate users with AWS Cognito",
    long_description=long_description,
    long_description_content_type="text/markdown",
    py_modules=["flask_awscognito"],
    packages=find_packages(),
    zip_safe=False,
    include_package_data=True,
    platforms="any",
    install_requires=["Flask", "python-jose", "requests"],
    tests_require=[tests_require],
    extras_require={"tests": tests_require},
    python_requires=">=3.6",
    classifiers=[
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
