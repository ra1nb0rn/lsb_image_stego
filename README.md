# LSB Image Steganography Tool
A small tool to perform password-based LSB image steganography

<p>
<a href="#"><img src="https://img.shields.io/badge/python-3.6%2B-red" alt="Python 3.6+"></a>
<a href="#"><img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-%23557ef6" alt="Platform: linux, macOS"></a>
<a href="https://github.com/DustinBorn/lsb_image_stego/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"></a>

</p>

## About
This tool can be used to perform password-based LSB image steganography. In other words, you can use this tool to hide a file inside an image. The secret file can only be recovered by supplying the correct password again using the reveal utility of the tool. Internally this works by encoding the secret data inside the least significant bits of the pixels contained in the image. The positions of the utilized pixels are computing randomly via a Pseudorandom Number Generator (PRNG) that is seeded with the password. You can find a visual explanation of LSB image steganography [here](https://itnext.io/steganography-101-lsb-introduction-with-python-4c4803e08041).


## Installation
For the tool to work properly, you have to install the required Python packages:
```
pip3 install -r requirements.txt
```


## Usage
To get the usage information, simply run ``./lsb_image_stego.py -h``:
<p>
<img src="https://github.com/DustinBorn/lsb_image_stego/blob/master/usage_info.png" width="60%" alt="Usage information">
</p>

As an example, to hide a file called ``secret.txt`` inside the cover image ``nature.png`` and name the output file ``beautiful_nature.png``, call the tool like so:
```
./lsb_image_stego.py -H -c nature.png -s secret.txt -o beautiful_nature.png
```
You will then be prompted to enter a password before the hiding starts. Note that the output will *always* be a PNG image. To recover the secret file ``secret.txt`` from the cover ``beautiful_nature.png``, simply call:
```
./lsb_image_stego.py -R -c beautiful_nature.png -o recovered_secret.txt
```
and enter your password again. Note that you can also supply your password via the ``-p`` argument for *batch processing*. However, under normal circumstances this may be considered *insecure*.


## License
This tool is licensed under the MIT license, see [here](https://github.com/DustinBorn/lsb_image_stego/blob/master/LICENSE).
