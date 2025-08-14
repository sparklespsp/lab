import cv2
import numpy as np
import matplotlib.pyplot as plt


def embed_watermark(image, watermark, alpha=0.1):
    # 将水印缩放到与图像大小相同
    watermark_resized = cv2.resize(watermark, (image.shape[1], image.shape[0]))

    # 将水印转换为灰度图
    watermark_gray = cv2.cvtColor(watermark_resized, cv2.COLOR_BGR2GRAY)

    # 使用 alpha 系数控制水印的强度
    watermarked_image = image.copy().astype(np.float32)
    watermarked_image[:, :, 0] += alpha * watermark_gray
    watermarked_image[:, :, 1] += alpha * watermark_gray
    watermarked_image[:, :, 2] += alpha * watermark_gray

    # 转回 uint8 类型
    watermarked_image = np.clip(watermarked_image, 0, 255
    _watermark(original_image, watermarked_image, alpha=0.1):

    # 计算图像之间的差异diff_image= np.abs(original_image - watermarked_image).astype(np.float32)

    # 恢复水印
    watermark_extracted = diff_image / alphawatermark_extracted = np.clip(watermark_extracted, 0, 255).astype(
        np.uint8)  # 加载图像和水印
    image = cv2.imread('image.jpg')
    # 主图像
    watermark = cv2.imread('watermark.jpg')

    # 1. 嵌入水印
    watermarked_image = embed_watermark(image, watermark)

    # 2.展示嵌入后的图像
    plt.figure(figsize=(10, 5))
    plt.subplot(1, 2, 1)
    plt.title('Original Image')
    plt.imshow(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))

    plt.subplot(1, 2, 2)
    plt.title('WatermarkedImage')
    plt.imshow(cv2.cvtColor(watermarked_image, cv2.COLOR_BGR2RGB))
    plt.show()

    # 3. 提取水印
    extracted_watermark = extract_watermark(image, watermarked_image)

    # 4. 展示提取的水印
    plt.figure(figsize=(5, 5))
    plt.imshow(cv2.cvtColor(extracted_watermark, cv2.COLOR_BGR2RGB))
    plt.title('Extracted Watermark')
    plt.show()  # 进行鲁棒性测试：翻转，平移，调整对比度等操作
    # 翻转图像
    flipped_image = cv2.flip(watermarked_image, 1)

    # 平移图像
    M = np.float32([[1, 0, 50], [0, 1, 50]])
    # 水平、垂直平移50像素
    shifted_image = cv2.warpAffine(watermarked_image, M, (watermarked_image.shape[1], watermarked_image.shape[0]))

    # 调整对比度
    alpha = 2.0
    # 对比度增强系数
    beta = 50
    # 亮度增强系数
    contrasted_image = cv2.convertScaleAbs(watermarked_image, alpha=alpha, beta=beta)

    # 显示操作结果
    plt.figure(figsize=(12, 8))

    plt.subplot(2, 2, 1)
    plt.title('Flipped Image')
    plt.imshow(cv2.cvtColor(flipped_image, cv2.COLOR_BGR2RGB))

    plt.subplot(2, 2, 2)
    plt.title('Shifted Image')
    plt.imshow(cv2.cvtColor(shifted_image, cv2.COLOR_BGR2RGB))

    plt.subplot(2, 2, 3)
    plt.title('Contrasted Image')
    plt.imshow(cv2.cvtColor(contrasted_image, cv2.COLOR_BGR2RGB))

    plt.subplot(2, 2, 4)
    plt.title('OriginalWatermarked Image')
    plt.imshow(cv2.cvtColor(watermarked_image, cv2.COLOR_BGR2RGB))

    plt.show()