#include <iostream>
#include <string>

int main() {
    std::string secret = "password='supersecretpass'";
    std::string database_ip = "10.0.0.5";
    std::cout << "Connected to " << database_ip << std::endl;
    return 0;
}
