from setuptools import setup, find_packages

setup(
    name='nexus-tools',
    zip_safe=False,
    description='Tools in order to  manage Nexus OSS repository',
    author='Sunjoo Park',
    author_email='all4dich@gmail.com',
    packages=['swtools'],
    package_dir={'': 'src'}
)
