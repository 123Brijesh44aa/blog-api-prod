-- CreateIndex
CREATE INDEX `AuditLog_userId_idx` ON `AuditLog`(`userId`);

-- CreateIndex
CREATE INDEX `Comment_postId_idx` ON `Comment`(`postId`);

-- CreateIndex
CREATE INDEX `Comment_userId_idx` ON `Comment`(`userId`);

-- CreateIndex
CREATE INDEX `Like_userId_idx` ON `Like`(`userId`);

-- CreateIndex
CREATE INDEX `Like_postId_idx` ON `Like`(`postId`);

-- CreateIndex
CREATE INDEX `Media_postId_idx` ON `Media`(`postId`);

-- CreateIndex
CREATE INDEX `Notification_userId_idx` ON `Notification`(`userId`);

-- CreateIndex
CREATE INDEX `PostTag_postId_idx` ON `PostTag`(`postId`);

-- CreateIndex
CREATE INDEX `PostTag_tagId_idx` ON `PostTag`(`tagId`);

-- CreateIndex
CREATE INDEX `Subscription_authorId_idx` ON `Subscription`(`authorId`);
