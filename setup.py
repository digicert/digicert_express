from setuptools import setup, find_packages

def readme():
    with open('README.rst') as f:
        return f.read()

setup(
    name='digicert-express',
    version='1.0.dev3',
    description='Express Install for DigiCert, Inc.',
    long_description=readme(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Topic :: Security',
        'Programming Language :: Python :: 2.5',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],
    url='https://github.com/digicert/digicert_express',
    author='DigiCert, Inc.',
    author_email='support@digicert.com',
    license='MIT',
    zip_safe=False,
    packages=find_packages(exclude=['tests.*', '*.tests.*', '*.tests', 'tests', 'scripts']),
    include_package_data=True,
    install_requires=[
        'python-augeas',
        'requests>=2.8.1',
        'ndg-httpsclient',
        'pyasn1',
        'pyOpenSSL'  # prefer OS install but we can try here, too
    ],
)
