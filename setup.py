from setuptools import setup, find_packages

setup(
    name="opsec-service-isolator",
    version="0.1.0",
    description="Decouple volatile scraping and identity-sentinel services into isolated microservices & micro-frontends with a Master Kill Switch.",
    author="Alejandro Londono",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.9",
    install_requires=[],
    extras_require={
        "dev": ["pytest>=7.0"],
    },
    entry_points={
        "console_scripts": [
            "opsec-service-isolator=opsec_service_isolator.cli:main",
        ],
    },
)
