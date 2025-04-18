# Elastic GDPR Scanner

The Elastic GDPR Scanner checks Elasticsearch instances for GDPR compliance.

The Elastic GDPR Scanner consists of 2 tools:
* the port scanner, that identifies Elasticsearch instances by port scanning the network,
* the GDPR checker, that tests Elasticsearch targets against lists of regexes.


**Disclamer: Vincent Maury or Elastic cannot be held responsible for the use of this script! Use it at your own risk**

## Getting Started

These instructions will get you a copy of the project up and running on your local machine.

### Prerequisites

This piece of python has no other pre-requisite than **Python 3**.<br/>
It should work on any platform.<br/>
No need for additional library.

### Get ready!

Just clone this repository:
```
git clone https://github.com/blookot/elastic-gdpr-scanner
```


## Scanning for Elasticsearch instances

TODO

## Running the GDPR scanner


### Running the script

Just run it:

```
python elastic-gdpr-scanner.py -h
```

TODO

## Authors

* **Vincent Maury** - *Initial commit* - [blookot](https://github.com/blookot)

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Check [this website](https://ipsec.pl/data-protection/2012/european-personal-data-regexp-patterns.html) for further regexes
* Found [this repo](https://github.com/tvfischer/gdpr-data-patterns-detection) which is a great initiative, but sadly empty...
* Inspired by my old vulnerability scanner startup... :-)
