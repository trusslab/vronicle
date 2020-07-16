#include <iostream>
#include "verifier.h"

int main(int argc, char** argv) {
	try {
		if (argc != 4) {
			throw std::logic_error{"Not enough arguments. \
									Usage: ./player <video_file> <sig_file> <pubkey_file>"};
		}

		Verifier verifier{argv[1], argv[2], argv[3]};
		verifier.verify();
	}

	catch (const std::exception &e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
