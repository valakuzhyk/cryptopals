package main

import (
	"fmt"

	"../crypto/utils"
)

func main() {
	fmt.Println(utils.EnglishScore("This is an english text."))
	fmt.Println(utils.EnglishScore("This is some gibberish that you don't know."))
	fmt.Println(utils.EnglishScore("Como estas? Muy bien? Pero, no estas ingles."))
	fmt.Println(utils.EnglishScore("18dtfvsdfiouhbnscv0923485upaslkjdnga;.sdr2056"))
	fmt.Println(utils.EnglishScore("q253s46edctuvgif9qwuejo;flsnzvc-51098u;asfgv,sdm"))
}
