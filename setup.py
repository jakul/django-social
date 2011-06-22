from setuptools import setup, find_packages

setup(
    name='django-social',
    version='0.0.1-dev',
    description='Tools to ease integration with social media',
    long_description=open('README.rst').read(),
    author='Craig Blaszczyk',
    author_email='craig.blaszczyk@gmail.com',
    url='https://github.com/jakul/django-social',
    download_url='https://github.com/jakul/django-social/downloads',
    license='BSD',
    packages=find_packages(exclude=('ez_setup', 'tests', 'example')),
    tests_require=[
        'django>=1.2,<1.4',
    ],
    include_package_data=True,
    zip_safe=False, # because we're including media that Django needs
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)