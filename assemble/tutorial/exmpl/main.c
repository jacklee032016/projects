#include <stdint.h>

const __float80 c_pi80=3.14159265358979323846w;
const __float80 c_sqrt2=1.41421356237309504880w;
extern __float80 as_pi80;
extern __float80 as_sqrt2;
extern __float80 co_sqrt2;
__float80 get_pi80(void);

int main(int argc, char * argv[], char * envp[]) {
    __float80 res;
    int j=sizeof(__float80);
    res=get_pi80();
    return 0;
}
