from setuptools import setup, find_packages

setup(
    name='digicert_express',
    version='1.0.dev1',
    description='Express Install for DigiCert, Inc.',
    long_description=open('README.md', 'r').read(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security',
    ],
    url='https://github.com/digicert/express_install',
    author='DigiCert, Inc.',
    author_email='support@digicert.com',
    license='MIT',
    zip_safe=False,
    packages=find_packages(exclude=['tests.*', '*.tests.*', '*.tests', 'tests', 'scripts']),
    include_package_data=True,
    install_requires=[
        'python-augeas',
        'requests',
    ],
)
